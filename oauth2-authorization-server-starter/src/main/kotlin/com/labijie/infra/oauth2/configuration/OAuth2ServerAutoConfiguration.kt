package com.labijie.infra.oauth2.configuration

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.OAuth2Constants.ENDPOINT_CHECK_TOKEN
import com.labijie.infra.oauth2.OAuth2ServerUtils.getIssuerOrDefault
import com.labijie.infra.oauth2.authentication.ResourceOwnerClientAuthenticationConverter
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationConverter
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationProvider
import com.labijie.infra.oauth2.component.IOAuth2ServerRSAKeyPair
import com.labijie.infra.oauth2.component.OAuth2ObjectMapperProcessor
import com.labijie.infra.oauth2.customizer.InfraClaimsContextCustomizer
import com.labijie.infra.oauth2.customizer.InfraOAuth2JwtTokenCustomizer
import com.labijie.infra.oauth2.mvc.CheckTokenController
import com.labijie.infra.oauth2.serialization.jackson.OAuth2CommonsJacksonModule
import com.labijie.infra.utils.ifNullOrBlank
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.autoconfigure.web.ServerProperties
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator
import org.springframework.security.web.SecurityFilterChain


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2DependenciesAutoConfiguration::class)
@Import(OAuth2ObjectMapperProcessor::class)
class OAuth2ServerAutoConfiguration {
    companion object {
        private val logger: Logger by lazy {
            LoggerFactory.getLogger(OAuth2ServerAutoConfiguration::class.java)
        }
    }


    @Bean
    fun jwkSource(keyGetter: IOAuth2ServerRSAKeyPair): JWKSource<SecurityContext> {
        val rsaKey = keyGetter.get()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource<SecurityContext> { jwkSelector, _ -> jwkSelector.select(jwkSet) }
    }

    //包装一下 , 避免和资源服务器的 bean 冲突
    @ConditionalOnMissingBean(IOAuth2ServerJwtCodec::class)
    @Bean
    fun oauth2ServerJwtCodec(
        settings: AuthorizationServerSettings,
        jwkSource: JWKSource<SecurityContext>
    ): OAuth2ServerJwtCodec {
        val issuer = settings.getIssuerOrDefault()
        return OAuth2ServerJwtCodec(issuer, jwkSource)
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder::class)
    fun jwtDecoder(serverJwtCodec: IOAuth2ServerJwtCodec): JwtDecoder {
        logger.info("OAuth2 authorization server jwt decoder used.")
        return serverJwtCodec.jwtDecoder()
    }

    @ConditionalOnMissingBean(ITokenIntrospectParser::class)
    @Bean
    fun oauth2ServerTokenIntrospectParser(oauth2ServerJwtCodec: IOAuth2ServerJwtCodec): ITokenIntrospectParser {
        return OAuth2ServerTokenIntrospectParser(oauth2ServerJwtCodec)
    }

    @Bean
    fun infraJwTokenCustomizer(): InfraOAuth2JwtTokenCustomizer {
        //See:
        // Only for self-contained token format
        return InfraOAuth2JwtTokenCustomizer()
    }

    @Bean
    protected fun infraClaimsContextCustomizer(): InfraClaimsContextCustomizer {
        // Only for reference token format
        return InfraClaimsContextCustomizer()
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AccessTokenGenerator::class)
    fun jwtGenerator(
        jwtCodec: IOAuth2ServerJwtCodec,
        customizer: InfraOAuth2JwtTokenCustomizer
    ): JwtGenerator {
        return JwtGenerator(jwtCodec.jwtEncoder()).apply {
            this.setJwtCustomizer(customizer)
        }
    }


    @Bean
    fun twoFactorSignInHelper(
        jwtGenerator: JwtGenerator,
        serverCodec: IOAuth2ServerJwtCodec,
        clientRepository: RegisteredClientRepository,
        eventPublisher: ApplicationEventPublisher,
        identityService: IIdentityService,
    ): TwoFactorSignInHelper {
        return TwoFactorSignInHelper(
            jwtGenerator,
            serverCodec,
            clientRepository,
            eventPublisher,
            identityService
        )
    }


    @Configuration(proxyBeanMethods = false)
    protected class SecurityFilterChainConfiguration : ApplicationContextAware {

        private lateinit var springContext: ApplicationContext


        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        fun authorizationServerSecurityFilterChain(
            http: HttpSecurity,
            clientRepository: RegisteredClientRepository,
            authorizationService: OAuth2AuthorizationService,
            commonsProperties: OAuth2ServerCommonsProperties,
        ): SecurityFilterChain {


            val sh = springContext.getBean(TwoFactorSignInHelper::class.java)

            val resourceOwnerClientAuthenticationConverter = ResourceOwnerClientAuthenticationConverter()
            val resourceOwnerPasswordAuthenticationConverter = ResourceOwnerPasswordAuthenticationConverter()
            val resourceOwnerPasswordAuthenticationProvider =
                ResourceOwnerPasswordAuthenticationProvider(sh, authorizationService, clientRepository)

            val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer()


            authorizationServerConfigurer
                .clientAuthentication { clientAuthentication ->
                    clientAuthentication
                        .authenticationConverter(resourceOwnerClientAuthenticationConverter)
                        .authenticationProviders { providers ->
                            providers.forEach {
                                if (ClientSecretAuthenticationProvider::class.java.isAssignableFrom(it::class.java)) {
                                    (it as ClientSecretAuthenticationProvider).setPasswordEncoder(NoopPasswordEncoder.INSTANCE)
                                }
                            }
                        }
                }
                .authorizationEndpoint { authorizationEndpoint ->
                    authorizationEndpoint.errorResponseHandler(OAuth2ExceptionHandler)
                }
                .tokenEndpoint {
                    it.accessTokenRequestConverter(resourceOwnerPasswordAuthenticationConverter)
                    it.authenticationProvider(resourceOwnerPasswordAuthenticationProvider)
                }

//            val controllerMatcher = ControllerClassRequestMatcher(requestMappingHandlerMapping, OAuth2ClientLoginController::class.java)
//
//            val endPoints = OrRequestMatcher(authorizationServerConfigurer.endpointsMatcher,controllerMatcher)
                http.securityMatcher(authorizationServerConfigurer.endpointsMatcher)
                .authorizeHttpRequests {
                    it.requestMatchers(HttpMethod.OPTIONS).permitAll()
                    it.anyRequest().authenticated()
                }
                .cors {

                }.with(authorizationServerConfigurer) { configurer ->
                    configurer.oidc(Customizer.withDefaults())
                }
                .sessionManagement {
                    it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    it.disable()
                }
                .exceptionHandling {
                    it.accessDeniedHandler(OAuth2ExceptionHandler)
                }

            logger.info("OAuth2 authorization server configured.")

            return http.formLogin {
                it.disable()
            }.applyCommonsPolicy(commonsProperties).build()
        }


        override fun setApplicationContext(applicationContext: ApplicationContext) {
            springContext = applicationContext
        }


    }



    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    fun checkTokenController(jwtCodec: IOAuth2ServerJwtCodec): CheckTokenController {
        return CheckTokenController(jwtCodec)
    }

    @Bean
    fun afterOauth2ServerRunner(applicationContext: ApplicationContext): CommandLineRunner {

        return object : CommandLineRunner {
            val settings = applicationContext.getBean(AuthorizationServerSettings::class.java)
            val keyGetter = applicationContext.getBean(IOAuth2ServerRSAKeyPair::class.java)
            val serverProperties = applicationContext.getBean(ServerProperties::class.java)


            override fun run(vararg args: String?) {

                if (settings.issuer.isNullOrBlank()) {
                    logger.warn(
                        "OAuth2 server issuer not set. Configure follow key to fix this:\n" +
                                OAuth2ServerProperties.ISSUER_KEY_PROPERTY_PATH
                    )
                }

                JacksonHelper.defaultObjectMapper.registerModules(OAuth2CommonsJacksonModule())
                JacksonHelper.webCompatibilityMapper.registerModules(OAuth2CommonsJacksonModule())

                if (keyGetter.isDefaultKeys()) {
                    val warn = StringBuilder()
                        .appendLine("The oauth2 authorization server uses a built-in rsa key, which can be a security issue.")
                        .appendLine("Configure following properties can be fix this warning:")
                        .appendLine("  1. ${OAuth2ServerProperties.PRIVATE_KEY_PROPERTY_PATH}")
                        .appendLine("  2. ${OAuth2ServerProperties.PUBLIC_KEY_PROPERTY_PATH}")
                        .appendLine("All above configuration can be pem file content, file path, or classpath resource file path.")
                        .toString()

                    logger.warn(warn)
                }

                val information = StringBuilder()
                information.appendLine("OAuth2 authorization server started.")
                information.appendLine("OAuth2 issuer: ${settings.issuer.ifNullOrBlank { "<null>" }}")
                information.appendLine()
                information.appendLine("The following endpoints are already active:")
                information.appendLine(settings.jwkSetEndpoint)
                information.appendLine(settings.tokenEndpoint)
                information.appendLine(ENDPOINT_CHECK_TOKEN)
                information.appendLine(settings.tokenIntrospectionEndpoint)
                information.appendLine(settings.tokenRevocationEndpoint)
                information.appendLine(settings.authorizationEndpoint)
                information.appendLine(settings.authorizationEndpoint)
                information.appendLine()
                information.appendLine("Use the configuration below to configure your resource server:")
                information.appendLine("spring.security.oauth2.resourceserver.jwt.issuer-uri: ${settings.issuer}")
                information.appendLine("spring.security.oauth2.resourceserver.jwt.jwk-set-uri: http://localhost:${serverProperties.port ?: 8080}${settings.jwkSetEndpoint}")

                logger.info(information.toString())
            }


        }
    }
}