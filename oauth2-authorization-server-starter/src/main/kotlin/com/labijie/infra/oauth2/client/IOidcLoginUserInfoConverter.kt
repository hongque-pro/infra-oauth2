package com.labijie.infra.oauth2.client

import com.nimbusds.jwt.SignedJWT

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
interface IOidcLoginUserInfoConverter {
    fun getProvider(): String
    fun convertFromToken(jwt: SignedJWT): OidcLoginUserInfo
}