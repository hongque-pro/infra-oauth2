package com.labijie.infra.oauth2.client.configuration

import com.labijie.infra.oauth2.client.apple.AppleAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.apple.AppleOAuth2UserService
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.web.client.RestClient

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AppleOAuth2ClientRegistrationProperties::class)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE)
class AppleOAuth2ClientAutoConfiguration {


    @Bean
    fun appleAuthorizationCodeTokenResponseClient(properties: AppleOAuth2ClientRegistrationProperties): AppleAuthorizationCodeTokenResponseClient
    {
        return AppleAuthorizationCodeTokenResponseClient(properties)
    }

    @Bean
    fun appleOAuth2UserService(resetClientBuilder: RestClient.Builder): AppleOAuth2UserService
    {
        return AppleOAuth2UserService(resetClientBuilder)
    }

}