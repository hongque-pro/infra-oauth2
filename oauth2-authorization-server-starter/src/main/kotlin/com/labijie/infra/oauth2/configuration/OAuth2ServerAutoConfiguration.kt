package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.Constants.DEFAULT_JWK_SET_ENDPOINT_PATH
import com.labijie.infra.oauth2.Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH
import com.labijie.infra.oauth2.IJwtCustomizer
import com.labijie.infra.oauth2.NoopPasswordEncoder
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationConverter
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationProvider
import com.labijie.infra.oauth2.mvc.CheckTokenController
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2TokenEndpointConfigurer
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
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
class OAuth2ServerAutoConfiguration(private val jwtCustomizers: ObjectProvider<IJwtCustomizer>) : ApplicationEventPublisherAware {

    companion object{
        val LOGGER by lazy {
            LoggerFactory.getLogger(OAuth2ServerAutoConfiguration::class.java)
        }
    }


    private lateinit var eventPublisher: ApplicationEventPublisher
    private fun getRsaKey(properties: OAuth2ServerProperties): RSAKey {
        val kp = if (properties.token.jwt.rsa.privateKey.isBlank() || properties.token.jwt.rsa.publicKey.isBlank()) {
            LOGGER.warn("Jwt token store rsa key pair not found, default key will be used.")
            properties.token.jwt.rsa.privateKey = Base64Utils.encodeToString(RsaUtils.defaultKeyPair.private.encoded)
            properties.token.jwt.rsa.publicKey = Base64Utils.encodeToString(RsaUtils.defaultKeyPair.public.encoded)
            RsaUtils.defaultKeyPair
        }else{
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
        return JWKSource<SecurityContext> { jwkSelector, securityContext -> jwkSelector.select(jwkSet) }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
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
        val eventPub = if(::eventPublisher.isInitialized) eventPublisher else null

        val authenticationManager = http.getSharedObject(AuthenticationManager::class.java)
        val providerSettings = http.getSharedObject(ProviderSettings::class.java)
        val authorizationService = http.getSharedObject(OAuth2AuthorizationService::class.java)
        val jwtEncoder = http.getSharedObject(JwtEncoder::class.java)
        val jwtDecoder = http.getSharedObject(JwtDecoder::class.java)
        val resourceOwnerPasswordAuthenticationProvider =
            ResourceOwnerPasswordAuthenticationProvider(
                authenticationManager,
                authorizationService,
                jwtEncoder,
                customizer,
                providerSettings,
                eventPub
            )

        // This will add new authentication provider in the list of existing authentication providers.
        http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider)
    }


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authorizationServerSecurityFilterChain(serverProperties: OAuth2ServerProperties, http: HttpSecurity): SecurityFilterChain? {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer<HttpSecurity>()

        authorizationServerConfigurer.withObjectPostProcessor(object: ObjectPostProcessor<OAuth2ClientAuthenticationProvider> {
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
    fun checkTokenController(jwtTokenDecoder: JwtDecoder): CheckTokenController {
        return CheckTokenController(jwtTokenDecoder)
    }
}