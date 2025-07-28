package com.labijie.infra.oauth2.configuration

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/3
 *
 */
internal class IgnoreCsrfConfigure() :
    AbstractHttpConfigurer<IgnoreCsrfConfigure, HttpSecurity>() {

    private val ignoreMatchers = mutableSetOf<RequestMatcher>()

    fun addMatcher(vararg matchers: RequestMatcher) {
        matchers.forEach {
            ignoreMatchers.add(it)
        }
    }

    override fun configure(http: HttpSecurity) {
        http.csrf {
            csrf->csrf.ignoringRequestMatchers(*ignoreMatchers.toTypedArray())
            csrf.disable()
        }
    }
}