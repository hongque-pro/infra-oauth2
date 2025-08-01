package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.ITokenIntrospectParser
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse
import org.slf4j.LoggerFactory
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.*
import java.net.URI
import java.net.URISyntaxException
import java.net.URL
import java.util.*

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 16:52
 * @Description:
 */

class LocalOpaqueTokenIntrospector(
    private val tokenParser: ITokenIntrospectParser
) : OpaqueTokenIntrospector {

    companion object {
        @JvmStatic
        val logger = LoggerFactory.getLogger(LocalOpaqueTokenIntrospector::class.java)
    }

    override fun introspect(token: String): OAuth2AuthenticatedPrincipal {
        val response = tokenParser.parse(token) as? TokenIntrospectionSuccessResponse
        if (response != null && response.isActive) {
            return convertClaimsSet(response)
        }
        logger.trace("Did not validate token since it is inactive")
        throw BadOpaqueTokenException("Provided token isn't active")
    }

    private fun convertClaimsSet(response: TokenIntrospectionSuccessResponse): OAuth2AuthenticatedPrincipal {
        val authorities: MutableCollection<GrantedAuthority> = ArrayList()
        val claims: MutableMap<String, Any> = response.toJSONObject()
        if (response.audience != null) {
            val audiences: MutableList<String> = ArrayList()
            for (audience in response.audience) {
                audiences.add(audience.value)
            }
            claims[OAuth2TokenIntrospectionClaimNames.AUD] = Collections.unmodifiableList(audiences)
        }
        if (response.clientID != null) {
            claims[OAuth2TokenIntrospectionClaimNames.CLIENT_ID] = response.clientID.value
        }
        if (response.expirationTime != null) {
            val exp = response.expirationTime.toInstant()
            claims[OAuth2TokenIntrospectionClaimNames.EXP] = exp
        }
        if (response.issueTime != null) {
            val iat = response.issueTime.toInstant()
            claims[OAuth2TokenIntrospectionClaimNames.IAT] = iat
        }
        if (response.issuer != null) {
            claims[OAuth2TokenIntrospectionClaimNames.ISS] = issuer(response.issuer.value)
        }
        if (response.notBeforeTime != null) {
            claims[OAuth2TokenIntrospectionClaimNames.NBF] = response.notBeforeTime.toInstant()
        }

//        val authorityPrefix = "SCOPE_"
//        if (response.scope != null) {
//            val scopes = Collections.unmodifiableList(response.scope.toStringList())
//            claims[OAuth2IntrospectionClaimNames.SCOPE] = scopes
//            for (scope in scopes) {
//                authorities.add(SimpleGrantedAuthority(this.authorityPrefix + scope))
//            }
//        }
        return OAuth2IntrospectionAuthenticatedPrincipal(claims, authorities)
    }

    private fun issuer(uri: String): String {
        return try {
            val uri = URI(uri)
            if(!uri.isAbsolute) {
                throw OAuth2IntrospectionException("Invalid ${OAuth2TokenIntrospectionClaimNames.ISS}, uri must be a absolute uri.\nvalue: $uri")
            }
            uri.toString()
        } catch (_: URISyntaxException) {
            throw OAuth2IntrospectionException(
                "Invalid " + OAuth2TokenIntrospectionClaimNames.ISS + " value: " + uri
            )
        }
    }
}