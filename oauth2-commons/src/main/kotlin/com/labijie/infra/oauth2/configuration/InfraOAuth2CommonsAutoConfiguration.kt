package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.OAuth2ExceptionHandler
import com.labijie.infra.oauth2.mvc.OAuth2ServerCommonsController
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/1
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
class InfraOAuth2CommonsAutoConfiguration: ApplicationContextAware {

    @Bean
    @ConditionalOnMissingBean
    fun oauth2ServerCommonsController(): OAuth2ServerCommonsController {
        return OAuth2ServerCommonsController()
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        OAuth2ExceptionHandler.setApplicationContext(applicationContext)
    }
}