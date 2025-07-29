package com.labijie.infra.oauth2.configuration

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/3
 *
 */


val EMPTY_REQUEST_MATCHER: RequestMatcher = RequestMatcher { request: HttpServletRequest? -> false }
val ANY_REQUEST_MATCHER: RequestMatcher = RequestMatcher { request: HttpServletRequest? -> true }

fun HttpSecurity.ignoreCSRF(): HttpSecurity {
     return this.csrf {
         it.requireCsrfProtectionMatcher(EMPTY_REQUEST_MATCHER)
         it.ignoringRequestMatchers(ANY_REQUEST_MATCHER)
     }
}

fun HttpSecurity.applyCommonsPolicy(disableCSRF: Boolean): HttpSecurity {

    val http = if (disableCSRF) {
        //使用 disable 单元测试任然需要验证 csrf
        this.csrf { it.requireCsrfProtectionMatcher(EMPTY_REQUEST_MATCHER) }
    } else {
        this.csrf {
            it.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        }
    }

    return http
        .httpBasic {
            it.disable()
        }.sessionManagement {
            it.sessionCreationPolicy(SessionCreationPolicy.NEVER)
            it.disable()
        }
}