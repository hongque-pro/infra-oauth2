package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.IIdentityService
import com.labijie.infra.oauth2.service.DefaultUserService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.config.BeanPostProcessor
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2ServerAutoConfiguration::class)
class OAuth2SecurityAutoConfiguration : BeanPostProcessor {

    @Autowired
    private lateinit var identityService: IIdentityService

    override fun postProcessAfterInitialization(bean: Any, beanName: String): Any? {
        if (bean is AuthenticationManagerBuilder) {
            bean
                .userDetailsService(DefaultUserService(this.identityService)) // .passwordEncoder(passwordEncoder())
                .and()
                .eraseCredentials(true)
        }
        return bean
    }

    @ConditionalOnClass(name = ["org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"])
    @Configuration(proxyBeanMethods = false)
    protected class ActuatorSecurityFilterConfiguration {
        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 1)
        fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {

            http.requestMatcher(EndpointRequest.toAnyEndpoint())
                .authorizeRequests { authorizeRequests ->
                    authorizeRequests
                        .anyRequest().permitAll()
                }
                .sessionManagement().disable()
                //.formLogin(withDefaults())
                .csrf().disable()
                .headers().frameOptions().sameOrigin()
            return http.build()
        }
    }


}