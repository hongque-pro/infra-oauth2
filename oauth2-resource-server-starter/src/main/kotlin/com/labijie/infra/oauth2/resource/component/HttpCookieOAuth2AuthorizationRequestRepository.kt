/**
 * @author Anders Xiao
 * @date 2024-06-18
 */
package com.labijie.infra.oauth2.resource.component

import com.labijie.infra.oauth2.resource.CookieUtils
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest


class HttpCookieOAuth2AuthorizationRequestRepository : AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    override fun loadAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest? {
        return CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)?.let {
            CookieUtils.deserialize(it, OAuth2AuthorizationRequest::class.java)
        }
    }

    override fun removeAuthorizationRequest(
        request: HttpServletRequest?,
        response: HttpServletResponse?
    ): OAuth2AuthorizationRequest? {
        if (request != null && response != null) {

            val r = loadAuthorizationRequest(request)
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME)
            return r
        }
        return null
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        if (authorizationRequest == null) {
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME)
            return
        }

        CookieUtils.addCookie(
            response,
            OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
            CookieUtils.serialize(authorizationRequest),
            COOKIE_EXPIRE_SECONDS
        )
        val redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME)
        if (!redirectUriAfterLogin.isNullOrBlank()) {
            CookieUtils.addCookie(
                response,
                REDIRECT_URI_PARAM_COOKIE_NAME,
                redirectUriAfterLogin,
                COOKIE_EXPIRE_SECONDS
            )
        }
    }

    companion object {
        const val OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME: String = "INFRA_OAUTH2_REQUEST"
        const val REDIRECT_URI_PARAM_COOKIE_NAME: String = "redirect_uri"
        private const val COOKIE_EXPIRE_SECONDS = 300
    }
}