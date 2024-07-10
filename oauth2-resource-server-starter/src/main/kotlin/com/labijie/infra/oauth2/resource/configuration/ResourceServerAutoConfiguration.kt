package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.resource.*
import com.labijie.infra.oauth2.resource.component.*
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
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.ImportRuntimeHints
import org.springframework.core.annotation.Order
import org.springframework.core.convert.TypeDescriptor
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.converter.ClaimConversionService
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import org.springframework.security.web.SecurityFilterChain
import org.springframework.stereotype.Repository
import java.io.IOException
import java.security.interfaces.RSAPublicKey


@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ResourceServerProperties::class)
@AutoConfigureAfter(OAuth2ResourceServerAutoConfiguration::class)
@ImportRuntimeHints(OAuth2SecurityRuntimeHints::class)
@Import(UnauthorizedController::class)
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
        @param: Autowired(required = false)
        private val clientRegistrationRepository: ClientRegistrationRepository?,
        @param: Autowired(required = false)
        private val cookieDecoder: IOAuth2TokenCookieDecoder?,
        private val resourceServerProperties: ResourceServerProperties,
        private val customizers: ObjectProvider<IOAuth2LoginCustomizer>,
        private val jwtDecoder: JwtDecoder,
        private val resourceConfigurers: ObjectProvider<IResourceAuthorizationConfigurer>
    ): ApplicationContextAware {

        private lateinit var applicationContext: ApplicationContext

        @Autowired(required = false)
        private var oauth2AuthorizationRequestRepository: AuthorizationRequestRepository<OAuth2AuthorizationRequest>? = null

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
                it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                it.disable()
            }
            //http.cors(Customizer.withDefaults())
            val settings = http
                .authorizeHttpRequests { authorize ->
                    authorize.requestMatchers(HttpMethod.OPTIONS).permitAll()
                    authorize.requestMatchers("/oauth2/unauthorized", "/oauth2/check_token").permitAll()
                    resourceConfigurers.orderedStream().forEach {
                        it.configure(authorize)
                    }
                    authorize.anyRequest().authenticated()
                }
            settings.oauth2ResourceServer { obj ->
                obj.jwt {
                    applyJwtConfiguration(it)
                }
                obj.bearerTokenResolver(CookieSupportedBearerTokenResolver(cookieDecoder).apply {
                    this.setBearerTokenFromCookieName(resourceServerProperties.bearerTokenResolver.allowCookieName)
                    this.setAllowUriQueryParameter(resourceServerProperties.bearerTokenResolver.allowUriQueryParameter)
                    this.setAllowFormEncodedBodyParameter(resourceServerProperties.bearerTokenResolver.allowFormEncodedBodyParameter)
                })
                obj.authenticationEntryPoint(OAuth2AuthenticationEntryPoint(applicationContext))
            }
            settings.authorizeHttpRequests {

            }
            settings.exceptionHandling {
                it.accessDeniedHandler(OAuth2ExceptionHandler.getInstance(this.applicationContext))
            }


            if(clientRegistrationRepository != null) {
                val requestRepository = oauth2AuthorizationRequestRepository ?: HttpCookieOAuth2AuthorizationRequestRepository()
                settings.oauth2Login {
                    it.authorizationEndpoint {
                        endpoint->
                        endpoint.authorizationRequestRepository(requestRepository)
                    }
                    customizers.orderedStream().forEach { c ->
                        c.customize(it)
                    }
                    it.loginPage("/oauth2/unauthorized")
                }
            }


            return settings.formLogin { it.disable() }.build()
        }

        fun applyJwtConfiguration(
            configurer: OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer
        ): OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer {
            configurer.decoder(jwtDecoder)

            return configurer
        }

        override fun setApplicationContext(applicationContext: ApplicationContext) {
            this.applicationContext = applicationContext
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