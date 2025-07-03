package com.labijie.infra.oauth2.configuration

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/3
 *
 */
fun HttpSecurity.ignoreCSRF(vararg  matchers: RequestMatcher): HttpSecurity {
    val config = this.getConfigurer(IgnoreCsrfConfigure::class.java)
    if(config != null) {
        config.addMatcher(*matchers)
    }else {
        this.with(IgnoreCsrfConfigure()) {
            it.addMatcher(*matchers)
        }
    }
    return this
}