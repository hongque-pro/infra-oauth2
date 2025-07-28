package com.labijie.infra.oauth2.authentication

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import java.util.*


class ResourceOwnerPasswordAuthenticationToken(
    private val clientId: String,
    private val clientCredential: Any,
    scopes: Set<String>? = null,
    additionalParameters: Map<String, Any>? = null
) :
    AbstractAuthenticationToken(Collections.emptyList()) {
    /**
     * Returns the requested scope(s).
     *
     * @return the requested scope(s), or an empty `Set` if not available
     */
    val scopes: Set<String> = scopes ?: HashSet()

    val additionalParameters: Map<String, Any> = additionalParameters ?: mapOf()

    companion object {
        private const val serialVersionUID = -6067207202119450764L
    }

    override fun getCredentials(): Any {
        return clientCredential
    }

    override fun getPrincipal(): Any {
        return clientId
    }

    override fun isAuthenticated(): Boolean {
        return super.isAuthenticated()
    }

    fun toOAuth2ClientAuthenticationToken(): OAuth2ClientAuthenticationToken {
        return OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientCredential, additionalParameters)
    }
}