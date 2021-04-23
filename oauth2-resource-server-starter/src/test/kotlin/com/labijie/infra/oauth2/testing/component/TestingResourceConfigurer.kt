package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.twoFactorRequired
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer

class TestingResourceConfigurer : IResourceAuthorizationConfigurer {
    override fun configure(registry: ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry) {
        registry.mvcMatchers("/test/2fac").twoFactorRequired()
    }
}