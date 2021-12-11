package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.CompositeOAuth2RequestValidator
import com.labijie.infra.oauth2.TokenStoreFactoryBean
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.error.IOAuth2ExceptionHandler
import com.labijie.infra.oauth2.filter.ClientDetailsArgumentResolver
import com.labijie.infra.oauth2.filter.ClientDetailsInterceptorAdapter
import com.labijie.infra.oauth2.preauth.TwoFactorPreAuthenticationProvider
import com.labijie.infra.oauth2.token.OAuth2TokenIntrospectParser
import com.labijie.infra.oauth2.token.UserInfoTokenEnhancer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.core.token.TokenService
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.security.oauth2.provider.token.*
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import java.util.*


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
@EnableAuthorizationServer
@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2CustomizationAutoConfiguration::class)
@AutoConfigureBefore(AuthorizationServerEndpointsConfiguration::class)
class OAuth2ServerAutoConfiguration @Autowired constructor(
        private val authenticationManager: AuthenticationManager,
        @param:Autowired(required = false)
        private val oauth2ExceptionHandler: IOAuth2ExceptionHandler?,
        private val serverProperties: OAuth2ServerProperties,
        private val oauth2RequestFactory: OAuth2RequestFactory,
        private val userDetailsService: UserDetailsService,
        private val clientDetailsService: ClientDetailsService,
        @Autowired
        tokenStore: TokenStore
) : AuthorizationServerConfigurerAdapter() {

    private val tokenStore = tokenStore ?: InMemoryTokenStore()

//    @Autowired
//    fun configTokenService(authorizationServerTokenServices: AuthorizationServerTokenServices) {
//
//        val tokenServices = authorizationServerTokenServices as?  DefaultTokenServices
//        createAuthServerTokenServices(tokenServices)
//    }


    fun createAuthServerTokenServices(tokenEnhancer: TokenEnhancer): DefaultTokenServices {
        val tokenServices = DefaultTokenServices()
        tokenServices.setClientDetailsService(clientDetailsService)
        tokenServices.setTokenStore(this.tokenStore)
        tokenServices.setTokenEnhancer(tokenEnhancer)
        tokenServices.setReuseRefreshToken(serverProperties.token.reuseRefreshToken)
        tokenServices.setSupportRefreshToken(serverProperties.token.refreshTokenEnabled)
        tokenServices.setAccessTokenValiditySeconds(
                1.coerceAtLeast(serverProperties.token.accessTokenExpiration.seconds.toInt())
        )
        tokenServices.setRefreshTokenValiditySeconds(
                1.coerceAtLeast(serverProperties.token.refreshTokenExpiration.seconds.toInt())
        )

        val provider = TwoFactorPreAuthenticationProvider()
        provider.setPreAuthenticatedUserDetailsService(
                UserDetailsByNameServiceWrapper(
                        userDetailsService
                )
        )
        tokenServices
                .setAuthenticationManager(ProviderManager(listOf<AuthenticationProvider>(provider)))

        return tokenServices
    }

    @Bean
    fun oauth2TokenIntrospectionParser(tokenStore: TokenStore): OAuth2TokenIntrospectParser {
        return OAuth2TokenIntrospectParser(tokenStore)
    }

    @Configuration
    @ConditionalOnBean(ClientDetailsService::class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    protected class ClientDetailsMvcAutoConfiguration : WebMvcConfigurer {

        @Autowired
        private lateinit var clientDetailsService: ClientDetailsService

        override fun addArgumentResolvers(resolvers: MutableList<HandlerMethodArgumentResolver>) {
            resolvers.add(ClientDetailsArgumentResolver(clientDetailsService))
        }

        override fun addInterceptors(registry: InterceptorRegistry) {
            registry.addInterceptor(ClientDetailsInterceptorAdapter(clientDetailsService))
        }
    }


    @Bean
    fun twoFactorSignInHelper(
            tokenStore: TokenStore,
            tokenServices: AuthorizationServerTokenServices,
            eventPublisher: ApplicationEventPublisher
    ): TwoFactorSignInHelper {

        return TwoFactorSignInHelper(
                serverProperties,
                tokenStore,
                eventPublisher,
                clientDetailsService,
                oauth2RequestFactory,
                tokenServices
        )
    }


    private class NonePasswordEncoder : PasswordEncoder {
        override fun encode(rawPassword: CharSequence): String {
            return rawPassword.toString()
        }

        override fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean {
            return rawPassword.toString() == encodedPassword
        }
    }

    override fun configure(security: AuthorizationServerSecurityConfigurer) {
        //兼容旧版代码， client detail secrect 不应该进行加密处理
        security.passwordEncoder(NonePasswordEncoder())
        security.checkTokenAccess("permitAll()")
        security.allowFormAuthenticationForClients()
    }


    @Throws(Exception::class)
    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) {
        endpoints.requestValidator(CompositeOAuth2RequestValidator(serverProperties))
        var accessTokenConverter: AccessTokenConverter? = null

        val enhancer = if (this.tokenStore is JwtTokenStore) {
            accessTokenConverter = TokenStoreFactoryBean.jwtAccessTokenConverter(serverProperties)
            val tokenEnhancerChain = TokenEnhancerChain()
            tokenEnhancerChain.setTokenEnhancers(listOf(UserInfoTokenEnhancer(), accessTokenConverter))
            tokenEnhancerChain
        } else { //redis
            UserInfoTokenEnhancer()
        }

        val tokenService = createAuthServerTokenServices(enhancer)
        endpoints.tokenServices(tokenService)
        endpoints.tokenEnhancer(enhancer)
        endpoints.tokenStore(tokenStore)

        if (accessTokenConverter != null) {
            endpoints.accessTokenConverter(accessTokenConverter)
        }
        endpoints.authenticationManager(authenticationManager)
        endpoints.userDetailsService(userDetailsService)
        endpoints.allowedTokenEndpointRequestMethods(HttpMethod.POST)
        if (oauth2ExceptionHandler != null) {
            endpoints.exceptionTranslator(oauth2ExceptionHandler)
        }
    }


    override fun configure(clients: ClientDetailsServiceConfigurer) {
        clients.withClientDetails(clientDetailsService)
    }

}