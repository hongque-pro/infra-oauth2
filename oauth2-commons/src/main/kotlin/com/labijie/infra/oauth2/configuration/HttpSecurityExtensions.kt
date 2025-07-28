package com.labijie.infra.oauth2.configuration

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.util.matcher.RequestMatcher
import kotlin.math.PI

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/3
 *
 */


val EMPTY_REQUEST_MATCHER: RequestMatcher = RequestMatcher { request: HttpServletRequest? -> false }
val ANY_REQUEST_MATCHER: RequestMatcher = RequestMatcher { request: HttpServletRequest? -> true }

fun HttpSecurity.ignoreCSRF(vararg matchers: RequestMatcher): HttpSecurity {
    val config = this.getConfigurer(IgnoreCsrfConfigure::class.java)
    if (config != null) {
        config.addMatcher(*matchers)
    } else {
        this.with(IgnoreCsrfConfigure()) {
            it.addMatcher(*matchers)
        }
    }
    return this
}

fun HttpSecurity.applyCommonsPolicy(disableCSRF: Boolean): HttpSecurity {

    val http = if (disableCSRF) {
        this.csrf { it.requireCsrfProtectionMatcher(EMPTY_REQUEST_MATCHER) }
    } else {
        this.csrf {
            it.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        }
    }

    return http
        .csrf {
            if (disableCSRF) {
                this.ignoreCSRF(ANY_REQUEST_MATCHER)
            }
        }
        .httpBasic {
            it.disable()
        }.sessionManagement {
            it.sessionCreationPolicy(SessionCreationPolicy.NEVER)
            it.disable()
        }
}