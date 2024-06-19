package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.OAuth2ServerUtils.getScopes
import com.labijie.infra.oauth2.OAuth2ServerUtils.isExpired
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse
import com.nimbusds.oauth2.sdk.id.Audience
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.BearerTokenError
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtException
import java.util.*

/**
 * return format
 * {
    "active" : true,
    "client_id" : "app",
    "iat" : 1638111239,
    "exp" : 1638114839,
    "scope" : [ ],
    "token_type" : "Bearer",
    "nbf" : 1638111239,
    "sub" : "app",
    "aud" : [ "app" ],
    "iss" : "https://labijie.com"
    }
 */
class OAuth2ServerTokenIntrospectParser(
    private val jwtCodec: IOAuth2ServerJwtCodec
) : ITokenIntrospectParser {
    companion object {
        val LOGGER: Logger by lazy {
            LoggerFactory.getLogger(OAuth2ServerTokenIntrospectParser::class.java)
        }
    }

    override fun parse(token: String): TokenIntrospectionResponse {
        if (token.isBlank()) {
            return TokenIntrospectionErrorResponse(BearerTokenError.MISSING_TOKEN)
        }

        val jwt: Jwt = try {
            jwtCodec.decode(token)
        } catch (jwtException: JwtException) {
            LOGGER.warn("Bad jwt token format for introspection.", jwtException)
            return TokenIntrospectionErrorResponse(BearerTokenError.INVALID_TOKEN)
        }

        if (jwt.isExpired) {
            return TokenIntrospectionSuccessResponse.Builder(false).build()
        }

        return TokenIntrospectionSuccessResponse.Builder(true)
            .expirationTime(jwt.expiresAt?.let {
                Date.from(it)
            })
            .scope(Scope.parse(jwt.getScopes()))
            .apply {
                val type = jwt.claims[OAuth2ParameterNames.TOKEN_TYPE]?.toString()
                if (type.isNullOrBlank()) {
                    this.tokenType(AccessTokenType.UNKNOWN)
                } else {
                    this.tokenType(AccessTokenType(jwt.tokenValue))
                }

                val audience = jwt.audience
                if (audience != null) {
                    this.audience(audience.map { Audience(it) })
                }

                val authorities = mutableSetOf<String>()
                if (jwt.claims.containsKey(OAuth2Constants.CLAIM_ROLES)) {
                    val roles = jwt.claims[OAuth2Constants.CLAIM_ROLES] as? Iterable<*>
                    roles?.forEach {
                        if (it != null) {
                            authorities.add("ROLE_$it")
                        }
                    }
                }

                if (jwt.claims.containsKey(OAuth2Constants.CLAIM_AUTHORITIES)) {
                    val roles = jwt.claims[OAuth2Constants.CLAIM_AUTHORITIES] as? Iterable<*>
                    roles?.forEach {
                        if (it != null) {
                            authorities.add(it.toString())
                        }
                    }
                }

                this.parameter(OAuth2Constants.CLAIM_AUTHORITIES, authorities)
            }
            .apply {
                jwt.claims.filter {
                    it.key != OAuth2Constants.CLAIM_AUTHORITIES &&
                            it.key != OAuth2Constants.CLAIM_ROLES &&
                            it.key != JwtClaimNames.AUD &&
                            it.key != JwtClaimNames.EXP
                }.forEach { (key, v) ->
                    this.parameter(key, v)
                }
            }.build()

    }
}