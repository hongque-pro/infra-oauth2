package com.labijie.infra.oauth2.events

import com.labijie.infra.oauth2.twoFactorPrincipal
import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.ApplicationEvent
import org.springframework.security.core.Authentication

class UserSignedInEvent(source: Any,
                        private val authentication: Authentication,
                        val httpServletRequest: HttpServletRequest?) : ApplicationEvent(source) {
    val principle by lazy {
        authentication.twoFactorPrincipal
    }
}