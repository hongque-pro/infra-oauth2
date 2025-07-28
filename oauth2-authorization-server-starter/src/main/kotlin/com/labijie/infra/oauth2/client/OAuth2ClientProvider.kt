package com.labijie.infra.oauth2.client

import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
data class OAuth2ClientProvider(
    val name: String,
    val authorizationUri: String? = null,
    /**
     * Token URI for the provider.
     */
    val tokenUri: String? = null,
    /**
     * User info URI for the provider.
     */
    val userInfoUri: String? = null,
    /**
     * User info authentication method for the provider.
     */
    val userInfoAuthenticationMethod: AuthenticationMethod? = null,

    /**
     * Name of the attribute that will be used to extract the username from the call
     * to 'userInfoUri'.
     */
    val userNameAttribute: String? = null,

    /**
     * JWK set URI for the provider.
     */
    val jwkSetUri: String? = null,

    /**
     * URI that can either be an OpenID Connect discovery endpoint or an OAuth 2.0
     * Authorization Server Metadata endpoint defined by RFC 8414.
     */
    val issuerUri: String? = null,

    val scopes: Set<String> = emptySet(),
) {

    companion object {
        private const val DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}"
    }

    private fun getBuilder(
        registrationId: String, method: ClientAuthenticationMethod,
    ): ClientRegistration.Builder {

        val builder: ClientRegistration.Builder =
            ClientRegistration.withRegistrationId(registrationId)
        builder.clientAuthenticationMethod(method)
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        builder.redirectUri(DEFAULT_REDIRECT_URL)

        tokenUri?.let { builder.tokenUri(it) }
        authorizationUri?.let { builder.authorizationUri(it) }
        userInfoUri?.let { builder.authorizationUri(it) }
        userInfoAuthenticationMethod?.let { builder.userInfoAuthenticationMethod(it) }
        userNameAttribute?.let { builder.userNameAttributeName(it) }
        jwkSetUri?.let { builder.jwkSetUri(it) }
        issuerUri?.let { builder.issuerUri(it) }

        if(scopes.isNotEmpty()) {
            builder.scope(scopes)
        }

        return builder
    }
}