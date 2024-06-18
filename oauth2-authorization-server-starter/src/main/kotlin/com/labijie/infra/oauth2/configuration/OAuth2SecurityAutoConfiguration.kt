package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.IIdentityService
import com.labijie.infra.oauth2.service.DefaultUserService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.config.BeanPostProcessor
import org.springframework.beans.factory.support.RootBeanDefinition
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Role
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.transaction.annotation.EnableTransactionManagement


@Configuration(proxyBeanMethods = false)
@EnableTransactionManagement
@AutoConfigureAfter(OAuth2ServerAutoConfiguration::class)
class OAuth2SecurityAutoConfiguration {

    @ConditionalOnClass(name = ["org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"])
    @Configuration(proxyBeanMethods = false)
    protected class ActuatorSecurityFilterConfiguration {
        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 1)
        fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {

            http.securityMatcher(EndpointRequest.toAnyEndpoint())
                .sessionManagement {
                    it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    it.disable()
                }
                .csrf {
                    it.disable()
                }
                .headers {
                    it.frameOptions {
                        h->h.sameOrigin()
                    }
                }
            return http.build()
        }
    }


}