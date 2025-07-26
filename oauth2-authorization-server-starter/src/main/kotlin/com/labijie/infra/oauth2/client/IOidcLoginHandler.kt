package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.mvc.OidcLoginRequest
import com.labijie.infra.oauth2.mvc.OidcLoginResponse
import com.nimbusds.jwt.SignedJWT
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
interface IOidcLoginHandler {
    fun handle(user: OAuth2LoginUser, request: OidcLoginRequest): OidcLoginResponse
}