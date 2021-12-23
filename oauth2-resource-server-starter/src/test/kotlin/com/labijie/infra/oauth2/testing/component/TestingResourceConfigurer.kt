package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.hasTokenAttributeValue
import com.labijie.infra.oauth2.resource.twoFactorRequired
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer

class TestingResourceConfigurer : IResourceAuthorizationConfigurer {
    override fun configure(registry: ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry) {
        registry.mvcMatchers("/test/2fac").twoFactorRequired()
                .mvcMatchers("/test/field-aaa-test").hasTokenAttributeValue("aaa", "test")
                .mvcMatchers("/test/field-bbb-test").hasTokenAttributeValue("bbb", "miss")
                .mvcMatchers("/test/role-aa-test").hasRole("aa")
                .mvcMatchers("/test/role-bb-test").hasRole("bb")
                .mvcMatchers("/test/permitAll").permitAll()
    }
}