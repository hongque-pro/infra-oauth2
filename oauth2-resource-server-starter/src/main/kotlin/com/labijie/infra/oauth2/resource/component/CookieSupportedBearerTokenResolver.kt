/**
 * @author Anders Xiao
 * @date 2024-06-19
 */
package com.labijie.infra.oauth2.resource.component

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver
import java.util.Base64

class CookieSupportedBearerTokenResolver(
    cookieDecoder: IOAuth2TokenCookieDecoder?) : BearerTokenResolver {
    private val defaultResolver = DefaultBearerTokenResolver()

    private val cookieDecoder = cookieDecoder ?: PlainTextCookieDecoder()

    private var cookieName: String? = null
    override fun resolve(request: HttpServletRequest): String? {
        if(RequestMatcherPostProcessor.isPermitAll(request)) {
            return null
        }

        var token = defaultResolver.resolve(request)

        if (token.isNullOrBlank() && !cookieName.isNullOrBlank()) {
            val cookie = request.cookies?.firstOrNull { c -> c.name.equals(cookieName, ignoreCase = true) }
            token = cookieDecoder.decode(cookie?.value)
        }
        return token
    }

    fun setAllowFormEncodedBodyParameter(allowFormEncodedBodyParameter: Boolean) {
        defaultResolver.setAllowFormEncodedBodyParameter(allowFormEncodedBodyParameter)
    }

    fun setAllowUriQueryParameter(allowUriQueryParameter: Boolean) {
        defaultResolver.setAllowUriQueryParameter(allowUriQueryParameter)
    }

    fun setBearerTokenHeaderName(bearerTokenHeaderName: String) {
        defaultResolver.setBearerTokenHeaderName(bearerTokenHeaderName)
    }

    fun setBearerTokenFromCookieName(cookieName: String?) {
        this.cookieName = cookieName
    }
}