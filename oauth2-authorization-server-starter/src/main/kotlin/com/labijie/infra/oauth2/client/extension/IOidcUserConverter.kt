package com.labijie.infra.oauth2.client.extension

import com.labijie.infra.oauth2.client.StandardOidcUserInfo
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
interface IOidcUserConverter {
    fun getProvider(): String
    fun convert(claimsSet: ClaimsSet): StandardOidcUserInfo
}