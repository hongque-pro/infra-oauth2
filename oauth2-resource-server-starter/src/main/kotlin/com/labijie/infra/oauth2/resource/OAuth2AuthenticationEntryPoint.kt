package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.OAuth2ExceptionHandler
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint
import org.springframework.security.web.AuthenticationEntryPoint
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationContext

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/23
 * @Description:
 */
class OAuth2AuthenticationEntryPoint() : AuthenticationEntryPoint {
    private val bearerTokenAuthenticationEntryPoint = BearerTokenAuthenticationEntryPoint()

    override fun commence(
        request: HttpServletRequest, response: HttpServletResponse,
        authException: AuthenticationException
    ) {
        OAuth2ExceptionHandler.onAuthenticationFailure(request, response, authException)
        //bearerTokenAuthenticationEntryPoint.commence(request, response, authException)
    }
}