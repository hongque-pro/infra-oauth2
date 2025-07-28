package com.labijie.infra.oauth2.client.configuration

import com.labijie.infra.oauth2.client.OAuth2ClientProvider
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
class OAuth2ClientOidcLoginProperties {
    /**
     * The issuer URI from the OpenID Connect provider, e.g., "https://example.com".
     * Used to validate the "iss" (issuer) claim in the ID token.
     */
    var issuerUri: String = ""

    /**
     * The URI to retrieve the JSON Web Key Set (JWKS).
     * Used to verify the digital signature of the ID token.
     */
    var jwkSetUri: String = ""

    /**
     * A comma-separated list of valid audience values.
     * Used to validate the "aud" (audience) claim in the ID token.
     */
    var audienceSet: String = ""

    /**
     * The name of the claim in the ID token that represents the user identifier.
     * Typically, it is "sub", but may vary depending on the identity provider.
     */
    var userIdAttribute: String = ""

    companion object {
        fun createFromProvider(provider: OAuth2ClientProvider, audienceSet: Set<String>): OAuth2ClientOidcLoginProperties {
            return OAuth2ClientOidcLoginProperties().apply {
                this.issuerUri = provider.issuerUri.orEmpty()
                this.jwkSetUri = provider.jwkSetUri.orEmpty()
                this.userIdAttribute = provider.userNameAttribute ?: IdTokenClaimNames.SUB
                this.audienceSet = audienceSet.joinToString(",")
            }
        }
    }
}