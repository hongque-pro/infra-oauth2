package com.labijie.dummy.auth

import com.labijie.infra.oauth2.configuration.OAuth2DependenciesAutoConfiguration
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder


@Configuration(proxyBeanMethods = false)
@AutoConfigureBefore(OAuth2DependenciesAutoConfiguration::class)
class DummyServerAutoConfiguration() {

    @Bean
    fun dummyController() : DummyController {
        return DummyController()
    }

    @Bean
    fun dummyIdentityService(passwordEncoder: PasswordEncoder): DummyIdentityService {
        return DummyIdentityService(passwordEncoder)
    }


    @Bean
    fun dummyResourceConfigurer(): DummyResourceConfigurer {
        return DummyResourceConfigurer()
    }
}