package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.OAuth2Constants.ENDPOINT_CHECK_TOKEN_ENDPOINT
import com.labijie.infra.oauth2.OAuth2Utils.loadContent
import com.labijie.infra.oauth2.authentication.ResourceOwnerClientAuthenticationConverter
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationConverter
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationProvider
import com.labijie.infra.oauth2.component.IOAuth2ServerSecretsStore
import com.labijie.infra.oauth2.mvc.CheckTokenController
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.CommandLineRunner
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
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2DependenciesAutoConfiguration::class)
class OAuth2ServerAutoConfiguration(
    private val serverProperties: OAuth2ServerProperties,
    private val jwtCustomizers: ObjectProvider<IJwtCustomizer>
) {

    companion object {

        private val LOGGER: Logger by lazy {
            LoggerFactory.getLogger(OAuth2ServerAutoConfiguration::class.java)
        }

    }

    private val useDefaultRsaKey
        get() = serverProperties.token.jwt.rsa.privateKey.isBlank() || serverProperties.token.jwt.rsa.publicKey.isBlank()

    private fun getRsaKey(secretsStore: IOAuth2ServerSecretsStore?): RSAKey {
        val kp = if (secretsStore != null) {
            val pub = RsaUtils.getPublicKey(secretsStore.getRsaPublicKey())
            val pri = RsaUtils.getPrivateKey(secretsStore.getRsaPrivateKey())
            KeyPair(pub, pri)
        } else if (useDefaultRsaKey) {
            serverProperties.token.jwt.rsa.privateKey =
                Base64.getEncoder().encodeToString(RsaUtils.defaultKeyPair.private.encoded)
            serverProperties.token.jwt.rsa.publicKey =
                Base64.getEncoder().encodeToString(RsaUtils.defaultKeyPair.public.encoded)
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
    fun jwkSource(@Autowired(required = false) secretsStore: IOAuth2ServerSecretsStore?): JWKSource<SecurityContext> {
        val rsaKey = getRsaKey(secretsStore)
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
        jwtDecoder: IOAuth2ServerJwtCodec
    ): TwoFactorSignInHelper {
        return TwoFactorSignInHelper(
            clientRepository,
            serverProperties,
            eventPublisher,
            jwtDecoder,
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
    protected class SecurityFilterChainConfiguration : ApplicationContextAware {

        private lateinit var springContext: ApplicationContext


        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        fun authorizationServerSecurityFilterChain(
            http: HttpSecurity,
            clientRepository: RegisteredClientRepository,
            authorizationService: OAuth2AuthorizationService,
            authorizationServerSettings: AuthorizationServerSettings
        ): SecurityFilterChain? {


            val sh = springContext.getBean(TwoFactorSignInHelper::class.java)

            val resourceOwnerClientAuthenticationConverter = ResourceOwnerClientAuthenticationConverter()
            val resourceOwnerPasswordAuthenticationConverter = ResourceOwnerPasswordAuthenticationConverter()
            val resourceOwnerPasswordAuthenticationProvider =
                ResourceOwnerPasswordAuthenticationProvider(sh, authorizationService, clientRepository)

            val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()


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
                    authorizationEndpoint.errorResponseHandler(OAuth2ExceptionHandler.INSTANCE)
                }
                .tokenEndpoint {
                    it.accessTokenRequestConverter(resourceOwnerPasswordAuthenticationConverter)
                    it.authenticationProvider(resourceOwnerPasswordAuthenticationProvider)
                }

                .oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0

            val endpointsMatcher = authorizationServerConfigurer.endpointsMatcher


            http.securityMatcher(endpointsMatcher)
                .authorizeHttpRequests {
                    it.requestMatchers(HttpMethod.OPTIONS).permitAll()
                    it.anyRequest().authenticated()
                }
                .csrf {
                    it.disable()
                }
                .cors {
                }.with(authorizationServerConfigurer) {

                }


            return http.formLogin(Customizer.withDefaults()).build()
        }

        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE + 1)
        fun checkTokenFilterChain(http: HttpSecurity): SecurityFilterChain {

            return http.securityMatcher(ENDPOINT_CHECK_TOKEN_ENDPOINT)
                .authorizeHttpRequests {
                    it.anyRequest().permitAll()
                }
                .csrf {
                    it.disable()
                }
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

    @Bean
    fun afterOauth2ServerRunner(applicationContext: ApplicationContext): CommandLineRunner {

        return object : CommandLineRunner {
            val settings = applicationContext.getBean(AuthorizationServerSettings::class.java)

            override fun run(vararg args: String?) {
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

                val information = StringBuilder()
                information.appendLine("The following endpoints are already active:")
                information.appendLine(settings.jwkSetEndpoint)
                information.appendLine(settings.tokenEndpoint)
                information.appendLine(ENDPOINT_CHECK_TOKEN_ENDPOINT)
                information.appendLine(settings.tokenRevocationEndpoint)
                information.appendLine(settings.authorizationEndpoint)

                LOGGER.info(information.toString())
            }


        }
    }
}