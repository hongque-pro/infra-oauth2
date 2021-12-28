package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.resource.ActuatorAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.LocalOpaqueTokenIntrospector
import com.labijie.infra.oauth2.resource.OAuth2AuthenticationEntryPoint
import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorSecurityExpressionHandler
import com.labijie.infra.oauth2.resource.resolver.BearTokenPrincipalResolver
import com.labijie.infra.oauth2.resource.resolver.BearTokenValueResolver
import com.labijie.infra.oauth2.resource.token.DefaultJwtAuthenticationConverter
import com.labijie.infra.utils.logger
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.convert.TypeDescriptor
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
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


@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ResourceServerProperties::class)
class ResourceServerAutoConfiguration(
    private val oauth2ResProperties: OAuth2ResourceServerProperties,
    private val resourceServerProperties: ResourceServerProperties
) : InitializingBean {


    companion object {
        private val OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Any::class.java)
        private val STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String::class.java)
        private val BOOL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean::class.java)


        private fun getConverter(targetDescriptor: TypeDescriptor): Converter<Any, *> {
            return Converter { source: Any? ->
                if (source == null) null else
                    ClaimConversionService.getSharedInstance().convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor)
            }
        }


//        fun genHS256Key(key: String): SecretKey {
//            val encodedKey: ByteArray = key.toByteArray(Charsets.UTF_8)
//            return SecretKeySpec(encodedKey, 0, encodedKey.size, JwsAlgorithms.HS256)
//        }
    }

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
                    Constants.CLAIM_USER_NAME to getConverter(STRING_TYPE_DESCRIPTOR),
                    Constants.CLAIM_TWO_FACTOR to getConverter(BOOL_TYPE_DESCRIPTOR),
                    Constants.CLAIM_USER_ID to getConverter(STRING_TYPE_DESCRIPTOR),
                    Constants.CLAIM_AUTHORITIES to collectionStringConverter
                )
            )
    }


    @Bean
    fun jwtDecoder(): JwtDecoder{
        val decoder = if (resourceServerProperties.jwt.rsaPubKey.isNotBlank()) {

            val rsaPubKey = OAuth2Utils.loadContent(resourceServerProperties.jwt.rsaPubKey, RsaUtils::getPublicKey)
                ?: throw IOException("${ResourceServerProperties.PUBLIC_KEY_CONFIG_PATH} is not an pem content or file/resource path.")

            NimbusJwtDecoder.withPublicKey(rsaPubKey)
                .build()
        } else if (!oauth2ResProperties.jwt.jwkSetUri.isNullOrBlank()) {
            NimbusJwtDecoder.withJwkSetUri(oauth2ResProperties.jwt.jwkSetUri)
                .build()
        } else if (oauth2ResProperties.jwt.publicKeyLocation?.exists() == true) {
            val pubKey = RsaUtils.getPublicKey(oauth2ResProperties.jwt.readPublicKey())
            NimbusJwtDecoder.withPublicKey(pubKey)
                .build()
        } else {
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
        private val jwtDecoder: JwtDecoder,
        private val oauth2ResProperties: OAuth2ResourceServerProperties,
        private val resourceServerProperties: ResourceServerProperties,
        private val resourceConfigurers: ObjectProvider<IResourceAuthorizationConfigurer>
    ) {


        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
        fun resourceServerSecurityChain(http: HttpSecurity): SecurityFilterChain {
            val settings = http
                .csrf().disable()
                .authorizeRequests { authorize ->
                    authorize.and().cors()
                    authorize.antMatchers(HttpMethod.OPTIONS).permitAll()
                    resourceConfigurers.orderedStream().forEach {
                        it.configure(authorize)
                    }

                    authorize
                        .expressionHandler(OAuth2TwoFactorSecurityExpressionHandler(http))
                        .anyRequest().authenticated()
                }
            settings.sessionManagement().disable()
            settings.oauth2ResourceServer { obj ->
                obj.jwt().also {
                    this.applyJwtConfiguration(it)
                }
                obj.authenticationEntryPoint(OAuth2AuthenticationEntryPoint())
            }
            settings.exceptionHandling {
                it.accessDeniedHandler(OAuth2ExceptionHandler.INSTANCE)
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


    override fun afterPropertiesSet() {
        val useDefaultPublic = resourceServerProperties.jwt.rsaPubKey.isBlank() &&
                oauth2ResProperties.jwt.jwkSetUri.isNullOrBlank() &&
                oauth2ResProperties.jwt.publicKeyLocation?.exists() != true

        if (useDefaultPublic) {
            val warn = StringBuilder()
                .appendLine("The oauth2 resource server uses a built-in public key for token decoding, which can be a security issue.")
                .appendLine("Configure one of following properties can be fix this warning:")
                .appendLine("  1. ${ResourceServerProperties.PUBLIC_KEY_CONFIG_PATH} (pem content/file path/classpath resource)")
                .appendLine("  2. spring.security.oauth2.resourceserver.jwt.public-key-location (resource path)")
                .appendLine("  3. spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
                .toString()
            logger.warn(warn)
        }
    }
}