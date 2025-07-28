package com.labijie.infra.oauth2.client.converter

import com.labijie.infra.oauth2.client.OAuth2ClientProviderNames
import com.labijie.infra.oauth2.client.StandardOidcUserInfo
import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
object AppleOidcUserConverter : IOidcUserConverter {
    override fun getProvider(): String {
        return OAuth2ClientProviderNames.APPLE
    }

    override fun convert(claimsSet: ClaimsSet): StandardOidcUserInfo {

        val info = StandardOidcUserInfoConverter.convert(claimsSet)
        if(info.email.isNotBlank()) {
            val hidden = claimsSet.getBooleanClaim("is_private_email") ?: false
            info.emailHidden = if (hidden) {
                true
            } else {
                info.email.endsWith("@privaterelay.appleid.com", true)
            }
        }
        return info
    }
}