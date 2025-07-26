package com.labijie.dummy

import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/26
 *
 */
@Configuration(proxyBeanMethods = false)
class HtmlAccessAutoConfiguration: IResourceAuthorizationConfigurer {
    override fun configure(registry: AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry) {
        registry.requestMatchers("/oauth2-login.html").permitAll()
    }
}