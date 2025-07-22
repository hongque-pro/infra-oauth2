package com.labijie.infra.oauth2.testing.configuration

import com.labijie.caching.configuration.CachingAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2DependenciesAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerSecurityAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.testing.component.OAuth2SignInTestingListener
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import org.springframework.boot.autoconfigure.ImportAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.crypto.password.PasswordEncoder

@EnableWebSecurity
@Configuration
@ImportAutoConfiguration(
    CachingAutoConfiguration::class,
    OAuth2DependenciesAutoConfiguration::class,
    OAuth2ServerAutoConfiguration::class,
    OAuth2ServerSecurityAutoConfiguration::class)
class OAuth2TestServerAutoConfiguration {

//    @Bean
//    fun dummyClientDetailServiceFactory(): TestingClientDetailServiceFactory {
//        return TestingClientDetailServiceFactory()
//    }


    @Bean
    fun testController() = TestController()

    @Bean
    fun testingIdentityService(passwordEncoder: PasswordEncoder): TestingIdentityService {
        return TestingIdentityService(passwordEncoder)
    }

    @Bean
    fun eventTestSubscription(): EventTestSubscription{
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