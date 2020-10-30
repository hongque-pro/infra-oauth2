package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.annotation.EnableOAuth2Server
import com.labijie.infra.oauth2.annotation.OAuth2ServerType
import com.labijie.infra.oauth2.testing.component.TestingClientDetailServiceFactory
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter

@Configuration
class OAuth2TestAutoConfiguration {

    @Bean
    fun dummyClientDetailServiceFactory(): TestingClientDetailServiceFactory {
        return TestingClientDetailServiceFactory()
    }

    @Bean
    fun testingIdentityService(): TestingIdentityService {
        return TestingIdentityService()
    }

    @Bean
    fun jacksonMessageConverter(): MappingJackson2HttpMessageConverter{
        return MappingJackson2HttpMessageConverter(JacksonHelper.defaultObjectMapper)
    }
}