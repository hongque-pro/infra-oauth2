package com.labijie.infra.oauth2.configuration

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository
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

fun HttpSecurity.applyCommonsPolicy(commonsProperties: OAuth2ServerCommonsProperties): HttpSecurity {

    val settings = commonsProperties.csrf
    val http = this.csrf {
        if(commonsProperties.csrf.disabled) {
            it.requireCsrfProtectionMatcher(EMPTY_REQUEST_MATCHER)
            it.ignoringRequestMatchers(ANY_REQUEST_MATCHER)
            it.disable()
        }else {
            when(settings.repository) {
                CsrfRepository.Cookie -> it.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                CsrfRepository.Session -> it.csrfTokenRepository(HttpSessionCsrfTokenRepository())
            }

        }
    }

    return http
        .httpBasic {
            it.disable()
        }.sessionManagement {
            it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            it.disable()
        }
}