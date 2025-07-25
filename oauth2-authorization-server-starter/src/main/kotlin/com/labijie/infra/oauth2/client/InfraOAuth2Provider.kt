package com.labijie.infra.oauth2.client

import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/22
 *
 */
object InfraOAuth2Provider {
    private const val DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";

    fun apple(registrationId: String = "apple"): ClientRegistration.Builder {
        val builder: ClientRegistration.Builder = getBuilder(
            registrationId,
            ClientAuthenticationMethod.CLIENT_SECRET_POST,
            DEFAULT_REDIRECT_URL
        )
        builder.tokenUri("https://appleid.apple.com/auth/token")
            .authorizationUri("https://appleid.apple.com/auth/authorize")
            .jwkSetUri("https://appleid.apple.com/auth/keys")
            .issuerUri("https://appleid.apple.com")
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .clientName(OAuth2ClientProviderNames.APPLE)
        return builder
    }

    private fun getBuilder(
        registrationId: String, method: ClientAuthenticationMethod, redirectUri: String
    ): ClientRegistration.Builder {
        val builder: ClientRegistration.Builder =
            ClientRegistration.withRegistrationId(registrationId)
        builder.clientAuthenticationMethod(method)
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        builder.redirectUri(redirectUri)
        return builder
    }
}