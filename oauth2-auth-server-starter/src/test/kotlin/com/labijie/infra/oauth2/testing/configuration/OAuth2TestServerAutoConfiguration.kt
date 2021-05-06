package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.oauth2.testing.component.OAuth2SignInTestingListener
import com.labijie.infra.oauth2.testing.component.TestingClientDetailServiceFactory
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OAuth2TestServerAutoConfiguration {

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
    fun oauth2SignInTestingListener(): OAuth2SignInTestingListener {
        return OAuth2SignInTestingListener()
    }
}