package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.error.IOAuth2ExceptionHandler
import com.labijie.infra.oauth2.filter.ClientDetailsArgumentResolver
import com.labijie.infra.oauth2.filter.ClientDetailsInterceptorAdapter
import com.labijie.infra.oauth2.preauth.TwoFactorPreAuthenticationProvider
import com.labijie.infra.oauth2.token.UserInfoTokenEnhancer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint
import org.springframework.security.oauth2.provider.token.*
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import java.util.*


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
@ConditionalOnBean(AuthorizationEndpoint::class)
@Configuration
@AutoConfigureAfter(OAuth2CustomizationAutoConfiguration::class)
@AutoConfigureBefore(AuthorizationServerEndpointsConfiguration::class)
class OAuth2ServerAutoConfiguration @Autowired constructor(
        @param:Autowired(required = false)
        @JvmField private val oauth2ExceptionHandler: IOAuth2ExceptionHandler?,
        @JvmField private val serverConfig: OAuth2ServerConfig,
        @JvmField private val oauth2RequestFactory: OAuth2RequestFactory,
        @param:Autowired(required = false)
        @JvmField private val accessTokenConverter: AccessTokenConverter?,
        @JvmField private val authenticationManager: AuthenticationManager,
        @JvmField private val userDetailsService: UserDetailsService,
        @JvmField private val clientDetailsService: ClientDetailsService,
        @JvmField private val tokenStore: TokenStore) : AuthorizationServerConfigurerAdapter() {

//    @Autowired
//    fun configTokenService(authorizationServerTokenServices: AuthorizationServerTokenServices) {
//
//        val tokenServices = authorizationServerTokenServices as?  DefaultTokenServices
//        createAuthServerTokenServices(tokenServices)
//    }

    private fun createAuthServerTokenServices( tokenEnhancer: TokenEnhancer): AuthorizationServerTokenServices {
        val tokenServices = DefaultTokenServices()
        tokenServices.setClientDetailsService(clientDetailsService)
        tokenServices.setTokenStore(this.tokenStore)
        tokenServices.setTokenEnhancer(tokenEnhancer)
        tokenServices.setReuseRefreshToken(serverConfig.token.reuseRefreshToken)
        tokenServices.setSupportRefreshToken(serverConfig.token.refreshTokenEnabled)
        tokenServices.setAccessTokenValiditySeconds(Math.max(1, serverConfig.token.accessTokenExpiration.seconds.toInt()))
        tokenServices.setRefreshTokenValiditySeconds(Math.max(1, serverConfig.token.refreshTokenExpiration.seconds.toInt()).toInt())

        val provider = TwoFactorPreAuthenticationProvider()
        provider.setPreAuthenticatedUserDetailsService(UserDetailsByNameServiceWrapper(
                userDetailsService))
        tokenServices
                .setAuthenticationManager(ProviderManager(Arrays.asList<AuthenticationProvider>(provider)))

        return tokenServices
    }

    @Configuration
    @ConditionalOnBean(ClientDetailsService::class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    protected class ClientDetailsMvcAutoConfiguration: WebMvcConfigurer {

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
    fun twoFactorSignInHelper(tokenServices: AuthorizationServerTokenServices): TwoFactorSignInHelper {
        return TwoFactorSignInHelper(clientDetailsService, oauth2RequestFactory, tokenServices)
    }

    override fun configure(security: AuthorizationServerSecurityConfigurer) {
        security.checkTokenAccess("permitAll()")
        security.allowFormAuthenticationForClients()
    }


    @Throws(Exception::class)
    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) {
        val enhancer = if (accessTokenConverter is JwtAccessTokenConverter) {
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
        if(oauth2ExceptionHandler != null) {
            endpoints.exceptionTranslator(oauth2ExceptionHandler)
        }
    }


    override fun configure(clients: ClientDetailsServiceConfigurer) {
        clients.withClientDetails(clientDetailsService)
    }

}