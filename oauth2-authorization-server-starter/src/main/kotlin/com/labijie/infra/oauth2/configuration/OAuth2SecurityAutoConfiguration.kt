package com.labijie.infra.oauth2.configuration

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2ServerAutoConfiguration::class)
class OAuth2SecurityAutoConfiguration {

    @ConditionalOnClass(name = ["org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"])
    @Configuration(proxyBeanMethods = false)
    protected class ActuatorSecurityFilterConfiguration {
        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 1)
        fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {

            http.securityMatcher(EndpointRequest.toAnyEndpoint())
                .sessionManagement {
                    it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    it.disable()
                }
                .csrf {
                    it.disable()
                }
            return http.build()
        }
    }


}