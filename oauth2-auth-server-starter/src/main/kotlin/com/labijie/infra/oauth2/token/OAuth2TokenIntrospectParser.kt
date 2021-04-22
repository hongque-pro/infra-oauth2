package com.labijie.infra.oauth2.token

import com.labijie.infra.oauth2.ITokenIntrospectParser
import com.labijie.infra.oauth2.copyAttributesTo
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse
import com.nimbusds.oauth2.sdk.id.Subject
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.BearerTokenError
import org.springframework.security.oauth2.provider.token.TokenStore
import java.time.Instant
import java.util.*

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 18:00
 * @Description:
 */

class OAuth2TokenIntrospectParser(private val tokenStore: TokenStore) : ITokenIntrospectParser {

    override fun parse(token: String): TokenIntrospectionResponse {
        if (token.isBlank()) {
            return TokenIntrospectionErrorResponse(BearerTokenError.MISSING_TOKEN)
        }

        val accessToken = this.tokenStore.readAccessToken(token)
        if (accessToken == null) {
            TokenIntrospectionErrorResponse(BearerTokenError.MISSING_TOKEN)
        }

        if (accessToken.isExpired) {
            return TokenIntrospectionErrorResponse(BearerTokenError.INVALID_TOKEN)
        }

        return TokenIntrospectionSuccessResponse.Builder(true)
                .expirationTime(Date.from(Instant.ofEpochMilli(accessToken.expiration.time)))
                .scope(Scope.parse(accessToken.scope))
                .apply {
                    if (accessToken.tokenType.isBlank()) {
                        this.tokenType(AccessTokenType.UNKNOWN)
                    } else {
                        this.tokenType(AccessTokenType(accessToken.tokenType))
                    }
                }
                .apply {
                    accessToken.additionalInformation.forEach { (key, v) ->
                        this.parameter(key, v)
                    }
                }.build()
    }
}