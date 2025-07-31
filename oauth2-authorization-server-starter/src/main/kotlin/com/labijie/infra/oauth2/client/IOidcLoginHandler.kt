package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.mvc.OidcLoginRequest
import com.labijie.infra.oauth2.mvc.OidcLoginResult

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
interface IOidcLoginHandler {
    fun handle(user: StandardOidcUser, request: OidcLoginRequest): OidcLoginResult
}