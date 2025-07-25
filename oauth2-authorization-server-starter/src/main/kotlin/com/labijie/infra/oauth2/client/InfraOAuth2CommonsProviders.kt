package com.labijie.infra.oauth2.client

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
object InfraOAuth2CommonsProviders {
    val APPLE by lazy {
        OAuth2ClientProperties.Provider().apply {
            tokenUri = "https://appleid.apple.com/auth/token"
            authorizationUri = "https://appleid.apple.com/auth/authorize"
            jwkSetUri = "https://appleid.apple.com/auth/keys"
            issuerUri = "https://appleid.apple.com"
            userInfoAuthenticationMethod = AuthenticationMethod.QUERY.value

            userNameAttribute = IdTokenClaimNames.SUB
        }
    }

    val DISCORD by lazy {
        OAuth2ClientProperties.Provider().apply {
            authorizationUri = "https://discord.com/oauth2/authorize"
            tokenUri = "https://discord.com/api/oauth2/token"
            userInfoUri = "https://discord.com/api/users/@me"
            userNameAttribute = "id" // Discord 的用户 ID 字段
            userInfoAuthenticationMethod = AuthenticationMethod.QUERY.value
            // Discord 没有 jwkSetUri / issuerUri，适用于 OAuth2，不是 OIDC
        }
    }
}