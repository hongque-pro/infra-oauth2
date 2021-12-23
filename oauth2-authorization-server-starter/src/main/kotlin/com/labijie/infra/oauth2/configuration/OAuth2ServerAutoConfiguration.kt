package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.OAuth2Utils.loadContent
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationConverter
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationProvider
import com.labijie.infra.oauth2.mvc.CheckTokenController
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2TokenEndpointConfigurer
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.util.Base64Utils
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2DependenciesAutoConfiguration::class)
class OAuth2ServerAutoConfiguration(
    private val serverProperties: OAuth2ServerProperties,
    private val jwtCustomizers: ObjectProvider<IJwtCustomizer>
) :
    InitializingBean {

    companion object {

        private val LOGGER: Logger by lazy {
            LoggerFactory.getLogger(OAuth2ServerAutoConfiguration::class.java)
        }

    }

    private val useDefaultRsaKey
        get() = serverProperties.token.jwt.rsa.privateKey.isBlank() || serverProperties.token.jwt.rsa.publicKey.isBlank()

    private fun getRsaKey(): RSAKey {
        val kp = if (useDefaultRsaKey) {
            serverProperties.token.jwt.rsa.privateKey =
                Base64Utils.encodeToString(RsaUtils.defaultKeyPair.private.encoded)
            serverProperties.token.jwt.rsa.publicKey =
                Base64Utils.encodeToString(RsaUtils.defaultKeyPair.public.encoded)
            RsaUtils.defaultKeyPair
        } else {
            val privateKey = loadContent(serverProperties.token.jwt.rsa.privateKey, RsaUtils::getPrivateKey)
                ?: throw IllegalArgumentException("${OAuth2ServerProperties.PRIVATE_KEY_PROPERTY_PATH} is an invalid")
            val publicKey = loadContent(serverProperties.token.jwt.rsa.publicKey, RsaUtils::getPublicKey)
                ?: throw IllegalArgumentException("${OAuth2ServerProperties.PUBLIC_KEY_PROPERTY_PATH} is an invalid")
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
    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey = getRsaKey()
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


    @Bean
    fun twoFactorSignInHelper(
        clientRepository: RegisteredClientRepository,
        eventPublisher: ApplicationEventPublisher,
        identityService: IIdentityService,
        JwtDecoder: IOAuth2ServerJwtCodec
    ): TwoFactorSignInHelper {
        return TwoFactorSignInHelper(
            clientRepository,
            serverProperties,
            eventPublisher,
            JwtDecoder,
            customizer,
            identityService
        )
    }


    private val customizer: OAuth2TokenCustomizer<JwtEncodingContext> by lazy {
        OAuth2TokenCustomizer { context: JwtEncodingContext ->
            jwtCustomizers.orderedStream().forEach {
                it.customizeToken(context)
            }
        }
    }

    @Configuration(proxyBeanMethods = false)
    protected class SecurityFilterChainConfiguration() : ApplicationContextAware {

        private lateinit var springContext: ApplicationContext

        private fun HttpSecurity.addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider() {
            val http = this
            val authenticationManager = http.getSharedObject(AuthenticationManager::class.java)
            val authorizationService = http.getSharedObject(OAuth2AuthorizationService::class.java)

            val sh = springContext.getBean(TwoFactorSignInHelper::class.java)

            sh.setup(authenticationManager, authorizationService)

            val resourceOwnerPasswordAuthenticationProvider =
                ResourceOwnerPasswordAuthenticationProvider(sh)

            // This will add new authentication provider in the list of existing authentication providers.
            http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider)
        }

        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        fun authorizationServerSecurityFilterChain(
            http: HttpSecurity
        ): SecurityFilterChain? {
            val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer<HttpSecurity>()

            authorizationServerConfigurer.withObjectPostProcessor(object :
                ObjectPostProcessor<OAuth2ClientAuthenticationProvider> {
                override fun <O : OAuth2ClientAuthenticationProvider> postProcess(provider: O): O {
                    provider.setPasswordEncoder(NoopPasswordEncoder.INSTANCE)
                    return provider
                }
            })

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
                tokenEndpoint.errorResponseHandler(OAuth2ExceptionHandler.INSTANCE)
            })


            authorizationServerConfigurer.authorizationEndpoint { authorizationEndpoint: OAuth2AuthorizationEndpointConfigurer ->
                authorizationEndpoint.consentPage(
                    "/oauth/consent"
                )
            }
            val endpointsMatcher = authorizationServerConfigurer.endpointsMatcher



            http.requestMatcher(endpointsMatcher)
                .authorizeRequests {
                    it.anyRequest().authenticated()
                }.csrf().disable()
                .cors().and()
                .apply(authorizationServerConfigurer)
            val securityFilterChain: SecurityFilterChain = http.formLogin(Customizer.withDefaults()).build()
            /**
             * Custom configuration for Resource Owner Password grant type. Current implementation has no support for Resource Owner
             * Password grant type
             */
            http.addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider()
            return securityFilterChain
        }

        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE + 1)
        fun checkTokenFilterChain(http: HttpSecurity): SecurityFilterChain {
            return http.mvcMatcher(Constants.DEFAULT_CHECK_TOKEN_ENDPOINT_PATH)
                .authorizeRequests {
                    it.anyRequest().permitAll()
                }
                .cors()
                .and()
                .csrf().disable()
                .build()
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

    override fun afterPropertiesSet() {
        if (useDefaultRsaKey) {
            val warn = StringBuilder()
                .appendLine("The oauth2 authorization server uses a built-in rsa key, which can be a security issue.")
                .appendLine("Configure following properties can be fix this warning:")
                .appendLine("  1. ${OAuth2ServerProperties.PRIVATE_KEY_PROPERTY_PATH}")
                .appendLine("  2. ${OAuth2ServerProperties.PUBLIC_KEY_PROPERTY_PATH}")
                .appendLine("All above configuration can be pem file content, file path, or classpath resource file path.")
                .toString()

            LOGGER.warn(warn)
        }
    }
}