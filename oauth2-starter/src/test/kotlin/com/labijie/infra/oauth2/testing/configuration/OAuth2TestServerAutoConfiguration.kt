package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.annotation.EnableOAuth2Server
import com.labijie.infra.oauth2.annotation.OAuth2ServerType
import com.labijie.infra.oauth2.testing.TestController
import com.labijie.infra.oauth2.testing.component.TestingClientDetailServiceFactory
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter

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

}