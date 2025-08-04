package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.component.OAuth2ObjectMapperProcessor
import org.springframework.beans.factory.config.BeanDefinition
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.Role
import org.springframework.core.Ordered

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/5
 *
 */

@Configuration(proxyBeanMethods = false)
@Import(OAuth2ObjectMapperProcessor::class)
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class OAuth2ServerBeanPostProcessorAutoConfiguration {
}