package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.oauth2.configuration.OAuth2DependenciesAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2SecurityAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration
import com.labijie.infra.oauth2.testing.ResourceTestController
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import com.labijie.infra.oauth2.testing.component.TestingResourceConfigurer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import

@Import(
    OAuth2DependenciesAutoConfiguration::class,
    OAuth2ServerAutoConfiguration::class,
    OAuth2SecurityAutoConfiguration::class,
    ResourceServerAutoConfiguration::class,)
@Configuration
class ResourceServerTestingConfiguration {

    @Bean
    fun resourceTestController() : ResourceTestController {
        return ResourceTestController()
    }

    @Bean
    fun testingIdentityService(): TestingIdentityService {
        return TestingIdentityService()
    }

    @Bean
    fun eventTestSubscription(): EventTestSubscription{
        return EventTestSubscription()
    }

    @Bean
    fun testingResourceConfigurer(): TestingResourceConfigurer{
        return TestingResourceConfigurer()
    }

}