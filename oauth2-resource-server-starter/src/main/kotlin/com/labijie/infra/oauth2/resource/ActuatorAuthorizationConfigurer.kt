package com.labijie.infra.oauth2.resource

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/11
 * @Description:
 */
class ActuatorAuthorizationConfigurer : IResourceAuthorizationConfigurer {

    override fun configure(registry: AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry) {
        registry.requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
    }
}