package com.labijie.infra.oauth2.testing.configuration

import com.labijie.caching.configuration.CachingAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2DependenciesAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerSecurityAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import org.springframework.boot.autoconfigure.ImportAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder

@ImportAutoConfiguration(
    CachingAutoConfiguration::class,
    OAuth2DependenciesAutoConfiguration::class,
    OAuth2ServerAutoConfiguration::class,
    OAuth2ServerSecurityAutoConfiguration::class,
    ResourceServerAutoConfiguration::class)
@Configuration
class ResourceServerTestingConfiguration(passwordEncoder: PasswordEncoder) {

    init {
        OAuth2TestingUtils.passwordEncoder = passwordEncoder
    }

    @Bean
    fun eventTestSubscription(): EventTestSubscription{
        return EventTestSubscription()
    }


}