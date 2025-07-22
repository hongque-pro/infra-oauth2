package com.labijie.infra.oauth2.client.apple

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
class AppleIdToken(header: JWSHeader, claimSet: JWTClaimsSet) : SignedJWT(header, claimSet) {

    private val idClaimSets = IDTokenClaimsSet(claimSet)

    val email by lazy {
        claimSet.getClaimAsString("email").orEmpty()
    }

    val emailVerified by lazy {
        claimSet.getBooleanClaim("email_verified") ?: false
    }

    val nonceSupported by lazy {
        claimSet.getBooleanClaim("nonce_supported") ?: false
    }

    val isPrivateEmail by lazy {
        val isPrivateEmail = claimSet.getBooleanClaim("is_private_email") ?: false
        if(isPrivateEmail) {
            true
        }else {
            email.endsWith("@privaterelay.appleid.com", true)
        }
    }

    val nonce: String?
        get() = idClaimSets.nonce?.value
}