package com.labijie.infra.oauth2.client.converter

import com.labijie.infra.oauth2.client.IOidcLoginUserInfoConverter
import com.labijie.infra.oauth2.client.OAuth2ClientProviderNames
import com.labijie.infra.oauth2.client.OidcLoginUserInfo
import com.nimbusds.jwt.SignedJWT

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
object AppleOidcUserInfoConverter : IOidcLoginUserInfoConverter {
    override fun getProvider(): String {
        return OAuth2ClientProviderNames.APPLE
    }

    override fun convertFromToken(jwt: SignedJWT): OidcLoginUserInfo {

        return OidcLoginUserInfo().apply {
            val email = jwt.jwtClaimsSet.getStringClaim("email").orEmpty()
            if(email.isNotBlank()) {
                this.email = email
                this.emailVerified = jwt.jwtClaimsSet.getBooleanClaim("email_verified") ?: false

                val hidden = jwt.jwtClaimsSet.getBooleanClaim("is_private_email") ?: false
                this.emailHidden = if (hidden) {
                    true
                } else {
                    email.endsWith("@privaterelay.appleid.com", true)
                }
            }
        }
    }
}