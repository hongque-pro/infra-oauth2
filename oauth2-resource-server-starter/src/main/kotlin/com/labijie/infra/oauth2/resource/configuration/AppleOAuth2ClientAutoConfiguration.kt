package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.resource.oauth2.apple.AppleAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.resource.oauth2.apple.AppleJwtDecoder
import com.labijie.infra.oauth2.resource.oauth2.apple.AppleOAuth2UserService
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered

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
    fun appleOAuth2UserService(): AppleOAuth2UserService
    {
        return AppleOAuth2UserService()
    }

    @Bean
    fun appleJwtDecoder(): AppleJwtDecoder {
        return AppleJwtDecoder()
    }
}