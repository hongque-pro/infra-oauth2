package com.labijie.infra.oauth2.configuration

import com.labijie.caching.ICacheManager
import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.Constants.DEFAULT_JWK_SET_ENDPOINT_PATH
import com.labijie.infra.oauth2.Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationConverter
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationProvider
import com.labijie.infra.oauth2.mvc.CheckTokenController
import com.labijie.infra.oauth2.service.CachingOAuth2AuthorizationService
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanInitializationException
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2TokenEndpointConfigurer
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder
import org.springframework.security.oauth2.server.authorization.*
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.util.Base64Utils
import java.lang.StringBuilder
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2DependenciesAutoConfiguration::class)
class OAuth2ServerAutoConfiguration(private val jwtCustomizers: ObjectProvider<IJwtCustomizer>) :
    ApplicationEventPublisherAware, ApplicationContextAware {

    companion object {
        private val LOGGER: Logger by lazy {
            LoggerFactory.getLogger(OAuth2ServerAutoConfiguration::class.java)
        }
    }


    private lateinit var eventPublisher: ApplicationEventPublisher
    private var signInHelper: TwoFactorSignInHelper? = null
    private lateinit var springContext: ApplicationContext

    private fun getRsaKey(properties: OAuth2ServerProperties): RSAKey {
        val kp = if (properties.token.jwt.rsa.privateKey.isBlank() || properties.token.jwt.rsa.publicKey.isBlank()) {
            LOGGER.warn("Jwt token store rsa key pair not found, default key will be used.")
            properties.token.jwt.rsa.privateKey = Base64Utils.encodeToString(RsaUtils.defaultKeyPair.private.encoded)
            properties.token.jwt.rsa.publicKey = Base64Utils.encodeToString(RsaUtils.defaultKeyPair.public.encoded)
            RsaUtils.defaultKeyPair
        } else {
            val privateKey = RsaUtils.getPrivateKey(properties.token.jwt.rsa.privateKey)
            val publicKey = RsaUtils.getPublicKey(properties.token.jwt.rsa.publicKey)
            KeyPair(publicKey, privateKey)
        }
        val publicKey: RSAPublicKey = kp.public as RSAPublicKey
        val privateKey: RSAPrivateKey = kp.private as RSAPrivateKey

        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    @Bean
    fun jwkSource(properties: OAuth2ServerProperties): JWKSource<SecurityContext> {
        val rsaKey = getRsaKey(properties)
        val jwkSet = JWKSet(rsaKey)
        return JWKSource<SecurityContext> { jwkSelector, _ -> jwkSelector.select(jwkSet) }
    }

    //包装一下 , 避免和资源服务器的 bean 冲突
    @ConditionalOnMissingBean(IOAuth2ServerJwtCodec::class)
    @Bean
    fun oauth2ServerJwtCodec(jwkSource: JWKSource<SecurityContext>): IOAuth2ServerJwtCodec {
        return OAuth2ServerJwtCodec(jwkSource)
    }

    @ConditionalOnMissingBean(ITokenIntrospectParser::class)
    @Bean
    fun oauth2ServerTokenIntrospectParser(oauth2ServerJwtCodec: IOAuth2ServerJwtCodec): ITokenIntrospectParser {
        return OAuth2ServerTokenIntrospectParser(oauth2ServerJwtCodec)
    }

//    @Bean
//    @ConditionalOnMissingBean(JwtEncoder::class)
//    fun jwtEncode(jwkSource: JWKSource<SecurityContext?>?): JwtEncoder {
//        return NimbusJwsEncoder(jwkSource)
//    }

    @Bean
    fun twoFactorSignInHelper(
        clientRepository: RegisteredClientRepository,
        serverProperties: OAuth2ServerProperties,
        eventPublisher: ApplicationEventPublisher,
        identityService: IIdentityService,
        JwtDecoder: IOAuth2ServerJwtCodec
    ): TwoFactorSignInHelper {
        if (signInHelper == null) {
            signInHelper = TwoFactorSignInHelper(
                clientRepository,
                serverProperties,
                eventPublisher,
                JwtDecoder,
                customizer,
                identityService
            )
        }
        return signInHelper!!
    }


    private val customizer: OAuth2TokenCustomizer<JwtEncodingContext> by lazy {
        OAuth2TokenCustomizer { context: JwtEncodingContext ->
            jwtCustomizers.orderedStream().forEach {
                it.customizeToken(context)
            }
        }
    }


    private fun HttpSecurity.addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider() {
        val http = this
        val eventPub = if (::eventPublisher.isInitialized) eventPublisher else null

        val authenticationManager = http.getSharedObject(AuthenticationManager::class.java)
        val providerSettings = http.getSharedObject(ProviderSettings::class.java)
        val authorizationService = http.getSharedObject(OAuth2AuthorizationService::class.java)

        val sh = signInHelper ?: throw BeanInitializationException("signInHelper bean was not ready.")

        sh.setup(authenticationManager, authorizationService)

        val helper = http.getSharedObject(TwoFactorSignInHelper::class.java)
        val resourceOwnerPasswordAuthenticationProvider =
            ResourceOwnerPasswordAuthenticationProvider(helper)

        // This will add new authentication provider in the list of existing authentication providers.
        http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider)
    }


    private fun getAuthService(serviceName: String): OAuth2AuthorizationService {
        val svc = when (serviceName) {
            "caching" -> {
                val cache = springContext.getBeanProvider(ICacheManager::class.java).firstOrNull()
                if (cache != null) {
                    CachingOAuth2AuthorizationService(cache)
                } else {
                    val msg = StringBuilder()
                        .appendLine("OAuth2 authorization service configured as 'caching', but ICacheManager bean missed, add one of follow packages to fix it:")
                        .appendLine("com.labijie:caching-kotlin-redis-starter")
                        .appendLine("com.labijie:caching-kotlin-redis-starter")
                        .appendLine("Now, InMemoryOAuth2AuthorizationService will be used !")
                        .toString()
                    LOGGER.warn(msg)
                    null
                }
            }
            "jdbc" -> {
                val jdbcTemplate = springContext.getBeanProvider(JdbcTemplate::class.java).firstOrNull()
                if (jdbcTemplate != null) {
                    val clientRepo = springContext.getBean(RegisteredClientRepository::class.java)
                    JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepo)
                } else {
                    val msg = StringBuilder()
                        .appendLine("OAuth2 authorization service configured as 'jdbc', but JdbcTemplate bean missed, add follow package to fix it:")
                        .appendLine("org.springframework.boot:spring-boot-starter-jdbc")
                        .appendLine("Now, InMemoryOAuth2AuthorizationService will be used !")
                        .toString()
                    LOGGER.warn(msg)
                    null
                }
            }
            else -> InMemoryOAuth2AuthorizationService()
        }
        return svc ?: InMemoryOAuth2AuthorizationService()

    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authorizationServerSecurityFilterChain(
        serverProperties: OAuth2ServerProperties,
        http: HttpSecurity
    ): SecurityFilterChain? {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer<HttpSecurity>()

        val sh = signInHelper ?: throw BeanInitializationException("Unable to get TwoFactorSignInHelper bean")
        http.setSharedObject(TwoFactorSignInHelper::class.java, sh)
        authorizationServerConfigurer.withObjectPostProcessor(object :
            ObjectPostProcessor<OAuth2ClientAuthenticationProvider> {
            override fun <O : OAuth2ClientAuthenticationProvider> postProcess(provider: O): O {
                provider.setPasswordEncoder(NoopPasswordEncoder.INSTANCE)
                return provider
            }
        })

        /**
         * http.apply(authorizationServerConfigurer.withObjectPostProcessor(new ObjectPostProcessor<OAuth2TokenEndpointFilter>() {
         * @Override
         * public <O extends OAuth2TokenEndpointFilter> O postProcess(O oauth2TokenEndpointFilter) {
         * oauth2TokenEndpointFilter.setAuthenticationConverter(new DelegatingAuthenticationConverter(
         * Arrays.asList(
         * new OAuth2AuthorizationCodeAuthenticationConverter(),
         * new OAuth2RefreshTokenAuthenticationConverter(),
         * new OAuth2ClientCredentialsAuthenticationConverter(),
         * new OAuth2ResourceOwnerPasswordAuthenticationConverter())));
         * return oauth2TokenEndpointFilter;
         * }
         * })
         * );
        </O></OAuth2TokenEndpointFilter> */
        http.apply(authorizationServerConfigurer.tokenEndpoint { tokenEndpoint: OAuth2TokenEndpointConfigurer ->
            tokenEndpoint.accessTokenRequestConverter(
                DelegatingAuthenticationConverter(
                    listOf(
                        OAuth2AuthorizationCodeAuthenticationConverter(),
                        OAuth2RefreshTokenAuthenticationConverter(),
                        OAuth2ClientCredentialsAuthenticationConverter(),
                        ResourceOwnerPasswordAuthenticationConverter()
                    )
                )
            )
        })


        val settings = ProviderSettings.builder()
            .authorizationEndpoint("/oauth/authorize")
            .tokenEndpoint("/oauth/token")
            .jwkSetEndpoint(DEFAULT_JWK_SET_ENDPOINT_PATH)
            .tokenRevocationEndpoint("/oauth/revoke")
            .tokenIntrospectionEndpoint(DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH)
            .oidcClientRegistrationEndpoint("/connect/register")
            .issuer(serverProperties.issuer)
            .build()


        authorizationServerConfigurer.providerSettings(settings)

        authorizationServerConfigurer.authorizationService(getAuthService(serverProperties.authorizationService))

        authorizationServerConfigurer.authorizationEndpoint { authorizationEndpoint: OAuth2AuthorizationEndpointConfigurer ->
            authorizationEndpoint.consentPage(
                "/oauth2/consent"
            )
        }
        val endpointsMatcher = authorizationServerConfigurer.endpointsMatcher
        http
            .requestMatcher(endpointsMatcher)
            .authorizeRequests(Customizer { authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
            })
            .csrf { csrf: CsrfConfigurer<HttpSecurity?> ->
                csrf.ignoringRequestMatchers(
                    endpointsMatcher
                )
            }
            .apply(authorizationServerConfigurer)
        val securityFilterChain: SecurityFilterChain = http.formLogin(Customizer.withDefaults()).build()
        /**
         * Custom configuration for Resource Owner Password grant type. Current implementation has no support for Resource Owner
         * Password grant type
         */
        http.addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider()
        return securityFilterChain
    }

    override fun setApplicationEventPublisher(applicationEventPublisher: ApplicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher
    }

    @Bean
    @ConditionalOnWebApplication(type=ConditionalOnWebApplication.Type.SERVLET)
    fun checkTokenController(jwtCodec: IOAuth2ServerJwtCodec): CheckTokenController {
        return CheckTokenController(jwtCodec)
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        springContext = applicationContext
    }
}