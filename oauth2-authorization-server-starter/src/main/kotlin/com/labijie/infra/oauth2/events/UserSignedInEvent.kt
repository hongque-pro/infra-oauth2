package com.labijie.infra.oauth2.events

import com.labijie.infra.oauth2.twoFactorPrincipal
import org.springframework.context.ApplicationEvent
import org.springframework.security.core.Authentication
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import javax.servlet.http.HttpServletRequest

class UserSignedInEvent(source: Any,
                        private val authentication: Authentication) : ApplicationEvent(source) {
    val principle by lazy {
        authentication.twoFactorPrincipal
    }

    val httpServletRequest: HttpServletRequest? = (RequestContextHolder.currentRequestAttributes() as? ServletRequestAttributes)?.request
}