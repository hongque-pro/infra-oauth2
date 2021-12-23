package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.OAuth2ExceptionHandler
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint
import org.springframework.security.web.AuthenticationEntryPoint
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/23
 * @Description:
 */
class OAuth2AuthenticationEntryPoint : AuthenticationEntryPoint {
    private val bearerTokenAuthenticationEntryPoint = BearerTokenAuthenticationEntryPoint()

    override fun commence(
        request: HttpServletRequest, response: HttpServletResponse,
        authException: AuthenticationException
    ) {
        OAuth2ExceptionHandler.INSTANCE.onAuthenticationFailure(request, response, authException)
        bearerTokenAuthenticationEntryPoint.commence(request, response, authException)
    }
}