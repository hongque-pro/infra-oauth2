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
object GoogleOidcUserInfoConverter : IOidcLoginUserInfoConverter {
    override fun getProvider(): String {
        return OAuth2ClientProviderNames.GOOGLE
    }

    override fun convertFromToken(jwt: SignedJWT): OidcLoginUserInfo {
        val info = OidcLoginUserInfo()
        val email = jwt.jwtClaimsSet.getStringClaim("email").orEmpty()
        if(email.isNotBlank()) {
            info.email = email
            info.emailVerified = jwt.jwtClaimsSet.getBooleanClaim("email_verified") ?: false
            info.emailHidden = false
        }
        info.avatar = jwt.jwtClaimsSet.getStringClaim("picture")
        info.username  = jwt.jwtClaimsSet.getStringClaim("name")

        return info
    }
}