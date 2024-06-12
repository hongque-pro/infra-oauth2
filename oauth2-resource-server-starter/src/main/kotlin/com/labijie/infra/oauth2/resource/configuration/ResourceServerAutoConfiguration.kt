package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.resource.ActuatorAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.LocalOpaqueTokenIntrospector
import com.labijie.infra.oauth2.resource.OAuth2AuthenticationEntryPoint
import com.labijie.infra.oauth2.resource.component.IOAuth2LoginCustomizer
import com.labijie.infra.oauth2.resource.component.IResourceServerSecretsStore
import com.labijie.infra.oauth2.resource.resolver.BearTokenPrincipalResolver
import com.labijie.infra.oauth2.resource.resolver.BearTokenValueResolver
import com.labijie.infra.oauth2.resource.token.DefaultJwtAuthenticationConverter
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.ImportRuntimeHints
import org.springframework.core.annotation.Order
import org.springframework.core.convert.TypeDescriptor
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.converter.ClaimConversionService
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import org.springframework.security.web.SecurityFilterChain
import java.io.IOException
import java.security.interfaces.RSAPublicKey


@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ResourceServerProperties::class)
@AutoConfigureAfter(OAuth2ResourceServerAutoConfiguration::class)
@ImportRuntimeHints(OAuth2SecurityRuntimeHints::class)
class ResourceServerAutoConfiguration(
    private val resourceServerProperties: ResourceServerProperties,
) {


    companion object {
        private val OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Any::class.java)
        private val STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String::class.java)
        private val BOOL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean::class.java)
        private val logger by lazy {
            LoggerFactory.getLogger(ResourceServerAutoConfiguration::class.java)
        }

        private fun getConverter(targetDescriptor: TypeDescriptor): Converter<Any, *> {
            return Converter { source: Any? ->
                if (source == null) null else
                    ClaimConversionService.getSharedInstance().convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor)
            }
        }
    }

    private var defaultPubKeyUsed = false

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationConverter::class)
    fun defaultJwtAuthenticationConverter(): DefaultJwtAuthenticationConverter {
        return DefaultJwtAuthenticationConverter()
    }

    @Bean
    fun bearTokenValueResolver(): BearTokenValueResolver {
        return BearTokenValueResolver()
    }

    @Bean
    fun bearTokenPrincipalResolver(): BearTokenPrincipalResolver {
        return BearTokenPrincipalResolver()
    }


    @Bean
    @ConditionalOnMissingBean(OpaqueTokenIntrospector::class)
    @ConditionalOnBean(ITokenIntrospectParser::class)
    fun localOpaqueTokenIntrospector(tokenIntrospectParser: ITokenIntrospectParser): LocalOpaqueTokenIntrospector {
        return LocalOpaqueTokenIntrospector(tokenIntrospectParser)
    }


    @Bean
    @ConditionalOnClass(name = ["org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"])
    fun actuatorConfigure(): ActuatorAuthorizationConfigurer {
        return ActuatorAuthorizationConfigurer()
    }

    private fun createOAuth2TokenValidator(): OAuth2TokenValidator<Jwt> {
        return DelegatingOAuth2TokenValidator(
            JwtTimestampValidator(resourceServerProperties.jwt.clockSkew)
        )
    }

    private fun createJwtClaimSetConverter(): MappedJwtClaimSetConverter {
        val collectionStringConverter = getConverter(
            TypeDescriptor.collection(MutableCollection::class.java, STRING_TYPE_DESCRIPTOR)
        )

        return MappedJwtClaimSetConverter
            .withDefaults(
                mapOf(
                    OAuth2Constants.CLAIM_USER_NAME to getConverter(STRING_TYPE_DESCRIPTOR),
                    OAuth2Constants.CLAIM_TWO_FACTOR to getConverter(BOOL_TYPE_DESCRIPTOR),
                    OAuth2Constants.CLAIM_USER_ID to getConverter(STRING_TYPE_DESCRIPTOR),
                    OAuth2Constants.CLAIM_AUTHORITIES to collectionStringConverter
                )
            )
    }


    @Bean
    @ConditionalOnMissingBean(JwtDecoder::class)
    fun jwtDecoder(
        @Autowired(required = false) secretsStore: IResourceServerSecretsStore?,
        serverProperties: ResourceServerProperties): JwtDecoder {

        val decoder = if(secretsStore != null ){

            val pubKey = RsaUtils.getPublicKey(secretsStore.getRsaPublicKey(serverProperties))
            NimbusJwtDecoder.withPublicKey(pubKey)
                .build()
        } else if (resourceServerProperties.jwt.rsaPubKey.isNotBlank()) {

            val rsaPubKey = OAuth2Utils.loadContent(resourceServerProperties.jwt.rsaPubKey, RsaUtils::getPublicKey)
                ?: throw IOException("${ResourceServerProperties.PUBLIC_KEY_CONFIG_PATH} is not an pem content or file/resource path.")

            NimbusJwtDecoder.withPublicKey(rsaPubKey)
                .build()
        } else {
            defaultPubKeyUsed = true
            NimbusJwtDecoder.withPublicKey(RsaUtils.defaultKeyPair.public as RSAPublicKey)
                .build()
        }

        val withClockSkew: OAuth2TokenValidator<Jwt> = createOAuth2TokenValidator()
        decoder.setJwtValidator(withClockSkew)

        val converter = createJwtClaimSetConverter()
        decoder.setClaimSetConverter(converter)
        return decoder
    }


    @Configuration(proxyBeanMethods = false)
    class ResourceServerSecurityFilterChainConfiguration(
        private val customizers: ObjectProvider<IOAuth2LoginCustomizer>,
        private val jwtDecoder: JwtDecoder,
        private val resourceConfigurers: ObjectProvider<IResourceAuthorizationConfigurer>
    ) {


        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
        fun resourceServerSecurityChain(http: HttpSecurity): SecurityFilterChain {

            http.csrf {
                it.disable()
            }
            http.httpBasic {
                it.disable()
            }

            http.sessionManagement {
                it.disable()
            }
            val settings = http
                .authorizeHttpRequests { authorize ->
                    authorize.requestMatchers(HttpMethod.OPTIONS).permitAll()
                    resourceConfigurers.orderedStream().forEach {
                        it.configure(authorize)
                    }
                    authorize.anyRequest().authenticated()
                }
            settings.oauth2ResourceServer { obj ->
                obj.jwt {
                    applyJwtConfiguration(it)
                }
                obj.authenticationEntryPoint(OAuth2AuthenticationEntryPoint())
            }
            settings.exceptionHandling {
                it.accessDeniedHandler(OAuth2ExceptionHandler.INSTANCE)
            }
            settings.oauth2Login {
                customizers.orderedStream().forEach {
                    c->c.customize(it)
                }
            }
            return settings.build()
        }

        fun applyJwtConfiguration(
            configurer: OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer
        ): OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer {
            configurer.decoder(jwtDecoder)

            return configurer
        }
    }

    @Bean
    fun afterOauth2ResourceServerRunner(): CommandLineRunner {
        return CommandLineRunner {
            if (defaultPubKeyUsed) {
                val warn = StringBuilder()
                    .appendLine("The oauth2 resource server uses a built-in public key for token decoding, which can be a security issue.")
                    .appendLine("Configure one of following properties can be fix this warning:")
                    .appendLine("  1. ${ResourceServerProperties.PUBLIC_KEY_CONFIG_PATH} (pem content/file path/classpath resource)")
                    .appendLine("  2. spring.security.oauth2.resourceserver.jwt.public-key-location (resource path)")
                    .appendLine("  3. spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
                    .appendLine("  4. implement a bean that inherits from IResourceServerSecretsStore interface")
                    .toString()
                logger.warn(warn)
            }
        }
    }
}