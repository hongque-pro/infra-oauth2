package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.oauth2.testing.ResourceTestController
import com.labijie.infra.oauth2.testing.component.TestingResourceConfigurer
import com.labijie.infra.oauth2.testing.component.TestingClientDetailServiceFactory
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ResourceServerTestingConfiguration {

    @Bean
    fun resourceTestController() : ResourceTestController {
        return ResourceTestController()
    }

    @Bean
    fun dummyClientDetailServiceFactory(): TestingClientDetailServiceFactory {
        return TestingClientDetailServiceFactory()
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