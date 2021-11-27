package com.labijie.infra.oauth2.authentication

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.util.*
import kotlin.collections.HashSet


class ResourceOwnerPasswordAuthenticationToken(
    private val grantType: AuthorizationGrantType,
    private val clientPrincipal: Authentication,
    scopes: Set<String>?,
    additionalParameters: Map<String, Any>?
) :
    AbstractAuthenticationToken(Collections.emptyList()) {

    /**
     * Returns the requested scope(s).
     *
     * @return the requested scope(s), or an empty `Set` if not available
     */
    val scopes: Set<String> = scopes ?: HashSet()

    /**
     * Returns the additional parameters.
     *
     * @return the additional parameters
     */
    val additionalParameters: Map<String, Any> = additionalParameters?: mapOf()


    override fun getPrincipal(): Any {
        return clientPrincipal
    }

    private val credentials: Any = ""

    override fun getCredentials(): Any {
        return credentials
    }

    companion object {
        private const val serialVersionUID = -6067207202119450764L
    }
}