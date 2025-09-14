package com.labijie.infra.oauth2.testing.configuration

import com.labijie.caching.configuration.CachingAutoConfiguration
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.configuration.InfraOidcUserConverterAutoConfiguration
import com.labijie.infra.oauth2.configuration.*
import com.labijie.infra.oauth2.testing.component.OAuth2SignInTestingListener
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.ImportAutoConfiguration
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.DefaultSecurityFilterChain


@Configuration
@ImportAutoConfiguration(CachingAutoConfiguration::class, InfraOAuth2CommonsAutoConfiguration::class)
class OAuth2TestServerAutoConfiguration {


    @Configuration(proxyBeanMethods = false)
    @AutoConfigureBefore(OAuth2ServerSecurityAutoConfiguration::class)
    class SecurityAutoConfig {
        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER)
        fun testServerChain(http: HttpSecurity): DefaultSecurityFilterChain? {
            return http

                .csrf { it.disable() }
                .securityMatcher("/**")
                .authorizeHttpRequests { authorize ->
                    authorize.requestMatchers("/test/fake-login").permitAll()
                    authorize.anyRequest().authenticated()
                }.build()
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration(
        OAuth2DependenciesAutoConfiguration::class,
        OAuth2ServerAutoConfiguration::class,
        OAuth2ServerSecurityAutoConfiguration::class,
        InfraOidcUserConverterAutoConfiguration::class,
        InfraOAuth2ClientProperties::class,
    )
    class OAuth2ServerImports

    @Bean
    fun testController() = TestController()

    @Bean
    fun testingIdentityService(passwordEncoder: PasswordEncoder): TestingIdentityService {
        return TestingIdentityService(passwordEncoder)
    }

    @Bean
    fun eventTestSubscription(): EventTestSubscription {
        return EventTestSubscription()
    }

    @Bean
    fun oauth2SignInTestingListener(): OAuth2SignInTestingListener {
        return OAuth2SignInTestingListener()
    }

//    @Bean
//    @Order(Ordered.LOWEST_PRECEDENCE)
//    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
//
//        http.authorizeHttpRequests {
//            it.requestMatchers("/fake-login").permitAll()
//            it.anyRequest().authenticated()
//        }
//        return http.build()
//    }

}