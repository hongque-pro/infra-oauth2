package com.labijie.infra.oauth2.client

import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.StandardClaimNames
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
object InfraOAuth2CommonsProviders {
    val Apple by lazy {
        OAuth2ClientProvider(
            OAuth2ClientProviderNames.APPLE,
            tokenUri = "https://appleid.apple.com/auth/token",
            authorizationUri = "https://appleid.apple.com/auth/authorize",
            jwkSetUri = "https://appleid.apple.com/auth/keys",
            issuerUri = "https://appleid.apple.com",
            userInfoAuthenticationMethod = AuthenticationMethod.QUERY,
            userNameAttribute = IdTokenClaimNames.SUB,
            scopes = setOf("name", "email")
        )
    }

    /**
     * refer: https://discord.com/developers/docs/topics/oauth2
     */
    val Discord by lazy {
        OAuth2ClientProvider(
            OAuth2ClientProviderNames.DISCORD,
            authorizationUri = "https://discord.com/oauth2/authorize",
            tokenUri = "https://discord.com/api/oauth2/token",
            userInfoUri = "https://discord.com/api/users/@me",
            userNameAttribute = "id", // Discord 的用户 ID 字段
            userInfoAuthenticationMethod = AuthenticationMethod.QUERY,
            scopes = setOf("identify", "email")
            // Discord 没有 jwkSetUri / issuerUri，适用于 OAuth2，不是 OIDC
        )
    }

    val Microsoft by lazy {
        OAuth2ClientProvider(
            OAuth2ClientProviderNames.DISCORD,
            authorizationUri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            tokenUri = "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            userInfoUri = "https://graph.microsoft.com/oidc/userinfo",
            userNameAttribute = StandardClaimNames.SUB,
            userInfoAuthenticationMethod = AuthenticationMethod.QUERY,
            scopes = setOf("openid ", "profile", "email")
            // Discord 没有 jwkSetUri / issuerUri，适用于 OAuth2，不是 OIDC
        )
    }
}