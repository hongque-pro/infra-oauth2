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

    override fun parse(tokenValue: String): TokenIntrospectionResponse {
        if (tokenValue.isBlank()) {
            return TokenIntrospectionErrorResponse(BearerTokenError.MISSING_TOKEN)
        }

        val token: Jwt = try {
            jwtCodec.decode(tokenValue)
        } catch (jwtException: JwtException) {
            LOGGER.warn("Bad jwt token format for introspection.", jwtException)
            return TokenIntrospectionErrorResponse(BearerTokenError.INVALID_TOKEN)
        }

        if (token.isExpired) {
            return TokenIntrospectionErrorResponse(BearerTokenError.INVALID_TOKEN)
        }

        return TokenIntrospectionSuccessResponse.Builder(true)
            .expirationTime(token.expiresAt?.let {
                Date.from(it)
            })
            .scope(Scope.parse(token.getScopes()))
            .apply {
                val type = token.claims[OAuth2ParameterNames.TOKEN_TYPE]?.toString()
                if (type.isNullOrBlank()) {
                    this.tokenType(AccessTokenType.UNKNOWN)
                } else {
                    this.tokenType(AccessTokenType(token.tokenValue))
                }

                val audience = token.audience
                if (audience != null) {
                    this.audience(audience.map { Audience(it) })
                }

                val authorities = mutableSetOf<String>()
                if (token.claims.containsKey(Constants.CLAIM_ROLES)) {
                    val roles = token.claims[Constants.CLAIM_ROLES] as? Iterable<*>
                    roles?.forEach {
                        if (it != null) {
                            authorities.add("ROLE_$it")
                        }
                    }
                }

                if (token.claims.containsKey(Constants.CLAIM_AUTHORITIES)) {
                    val roles = token.claims[Constants.CLAIM_AUTHORITIES] as? Iterable<*>
                    roles?.forEach {
                        if (it != null) {
                            authorities.add(it.toString())
                        }
                    }
                }

                this.parameter(Constants.CLAIM_AUTHORITIES, authorities)
            }
            .apply {
                token.claims.filter {
                    it.key != Constants.CLAIM_AUTHORITIES &&
                            it.key != Constants.CLAIM_ROLES &&
                            it.key != JwtClaimNames.AUD &&
                            it.key != JwtClaimNames.EXP
                }.forEach { (key, v) ->
                    this.parameter(key, v)
                }
            }.build()

    }
}