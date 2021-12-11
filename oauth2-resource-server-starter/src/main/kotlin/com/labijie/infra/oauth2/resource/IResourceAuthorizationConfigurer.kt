package com.labijie.infra.oauth2.resource

import org.springframework.core.Ordered
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer

interface IResourceAuthorizationConfigurer: Ordered {
    override fun getOrder(): Int = 100
    fun configure(registry: ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry)
}