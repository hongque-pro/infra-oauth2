package com.labijie.infra.oauth2.annotation

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/26
 *
 */
@Configuration(proxyBeanMethods = false)
internal class NoSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun noSecurityMarker(): NoSecurityMarker {
        return NoSecurityMarker()
    }

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { it.anyRequest().permitAll() }
            .csrf { it.disable() }
            .formLogin { it.disable() }
            .httpBasic { it.disable() }
        return http.build()
    }
}

