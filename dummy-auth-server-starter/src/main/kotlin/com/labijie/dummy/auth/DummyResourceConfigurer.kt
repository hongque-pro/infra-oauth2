package com.labijie.dummy.auth

import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.hasTokenAttributeValue
import com.labijie.infra.oauth2.resource.twoFactorRequired
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/19
 *
 */
class DummyResourceConfigurer : IResourceAuthorizationConfigurer {

    override fun configure(registry: AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry) {
        registry.requestMatchers("/test/2fac").twoFactorRequired()
            .requestMatchers("/test/field-aaa-test").hasTokenAttributeValue("aaa", "test")
            .requestMatchers("/test/field-bbb-test").hasTokenAttributeValue("bbb", "miss")
            .requestMatchers("/test/role-aa-test").hasRole("aa")
            .requestMatchers("/test/role-bb-test").hasRole("bb")
            .requestMatchers("/test/permitAll").permitAll()
            .requestMatchers("/test/fake-login/*").permitAll()
    }
}