package com.labijie.infra.oauth2.client.converter

import com.labijie.infra.oauth2.client.OAuth2ClientProviderNames
import com.labijie.infra.oauth2.client.StandardOidcUserInfo
import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/28
 *
 */
object GithubOidcUserConverter : IOidcUserConverter {
    override fun getProvider(): String {
        return OAuth2ClientProviderNames.GITHUB
    }

    /**
     * [Refer: github doc](https://docs.github.com/en/rest/users/users)
     */
    override fun convert(claimsSet: ClaimsSet): StandardOidcUserInfo {
        val info = StandardOidcUserInfoConverter.convert(claimsSet)

        claimsSet.getStringClaim("avatar_url")?.let {
            info.picture = it
        }

        //github 只有验证过的 email 才能设为 primary email.
        if(info.email.isNotBlank()) {
            info.emailHidden = info.email.endsWith("@users.noreply.github.com")
        }
        return info
    }
}