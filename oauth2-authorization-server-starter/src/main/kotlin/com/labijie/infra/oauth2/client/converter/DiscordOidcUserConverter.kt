package com.labijie.infra.oauth2.client.converter

import com.labijie.infra.oauth2.client.OAuth2ClientProviderNames
import com.labijie.infra.oauth2.client.StandardOidcUserInfo
import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
object DiscordOidcUserConverter : IOidcUserConverter {
    override fun getProvider(): String {
        return OAuth2ClientProviderNames.DISCORD
    }

    /**
     * Read discord user.
     *
     * [Refer Discord docs](https://discord.com/developers/docs/resources/user#user-object)
     */
    override fun convert(claimsSet: ClaimsSet): StandardOidcUserInfo {
        val info = StandardOidcUserInfo()

        claimsSet.getStringClaim("email")?.let {
            info.email = it
        }

        claimsSet.getBooleanClaim("verified")?.let {
            info.emailVerified = it
        }

        val userId = claimsSet.getStringClaim("id")
        val avatar = claimsSet.getStringClaim("avatar")

        if(!userId.isNullOrBlank() && !avatar.isNullOrBlank()) {
            info.picture = "https://cdn.discordapp.com/avatars/$userId/$${avatar}.png"
        }

        claimsSet.getStringClaim("username")?.let {
            info.username = claimsSet.getStringClaim("username")
        }

        return info
    }

}