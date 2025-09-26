package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.annotation.ConditionalOnSecurityEnabled
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/30
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnSecurityEnabled
class OAuth2DefaultsAutoConfiguration {

    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(OAuth2DefaultsAutoConfiguration::class.java)
        }
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizationService::class)
    fun inMemoryOAuth2AuthorizationService(): InMemoryOAuth2AuthorizationService{

        logger.info("OAuth2 authorization service use InMemoryOAuth2AuthorizationService, this implementation only supports single instances.")
        return InMemoryOAuth2AuthorizationService()
    }


}