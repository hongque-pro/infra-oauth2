package com.labijie.infra.oauth2.authentication

import jakarta.servlet.http.HttpServletResponse
import org.apache.catalina.authenticator.AuthenticatorBase
import org.apache.catalina.connector.Request
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider
import java.util.*
import kotlin.collections.HashSet


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