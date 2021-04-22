package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.endpoint.IntrospectEndpoint
import com.labijie.infra.oauth2.endpoint.JwkSetEndpoint
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.Primary
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.http.HttpServletRequest


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 * 用户必须实现的依赖
 */

@AutoConfigureAfter(AuthenticationProvider::class)
@AutoConfigureBefore(UserDetailsServiceAutoConfiguration::class)
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2ServerProperties::class)
@Import(IntrospectEndpoint::class, JwkSetEndpoint::class)
class OAuth2CustomizationAutoConfiguration(
        @JvmField private val identityService: IIdentityService) : WebSecurityConfigurerAdapter() {

    @Bean
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

    @Configuration
    protected class OAuth2PasswordEncoderConfiguration {

        @Bean
        @ConditionalOnMissingBean(PasswordEncoder::class)
        fun oauth2PasswordEncoder(): PasswordEncoder {
            val encoder = PasswordEncoderFactories .createDelegatingPasswordEncoder() as DelegatingPasswordEncoder
            return encoder.apply {
                this.setDefaultPasswordEncoderForMatches(BCryptPasswordEncoder())
            }
        }
    }

    @Configuration
    protected class AuthenticationProviderAutoConfiguration {
        @Primary
        @Bean
        fun defaultAuthenticationProvider(eventPublisher: ApplicationEventPublisher, passwordEncoder: PasswordEncoder, userDetailService: DefaultUserService): DefaultAuthenticationProvider {
            return DefaultAuthenticationProvider(
                    eventPublisher,
                    userDetailService,
                    passwordEncoder
            )
        }
    }


    @Bean
    override fun userDetailsService(): UserDetailsService {
        return DefaultUserService(identityService)
    }


    override fun configure(http: HttpSecurity) {
        http
                .authorizeRequests()
                .mvcMatchers(Constants.DEFAULT_JWK_SET_ENDPOINT_PATH, Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH).permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().ignoringRequestMatchers(RequestMatcher { request: HttpServletRequest -> Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH == request.requestURI })
    }

    @Primary
    @Bean
    fun defaultClientDetailsService(clientDetailsServiceFactory: IClientDetailsServiceFactory): ClientDetailsService {
        return clientDetailsServiceFactory.createClientDetailsService()
    }

    @Bean
    fun defaultOAuth2RequestFactory(clientDetailsService: ClientDetailsService): DefaultOAuth2RequestFactory {
        return DefaultOAuth2RequestFactory(clientDetailsService)
    }


    @Bean
    @ConditionalOnMissingBean(TokenStore::class)
    fun tokenStoreFactoryBean(
            serverProperties: OAuth2ServerProperties
    ): TokenStoreFactoryBean {
        return TokenStoreFactoryBean(serverProperties)
    }
}
