package com.labijie.infra.oauth2.client.apple

import com.nimbusds.jwt.SignedJWT

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
fun SignedJWT.toAppleIdToken(): AppleIdToken {
    return AppleIdToken(this.header, this.jwtClaimsSet)
}