package com.labijie.infra.oauth2.token

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.ITokenIntrospectionParser
import com.labijie.infra.oauth2.copyAttributesTo
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse
import com.nimbusds.oauth2.sdk.id.Subject
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.BearerTokenError
import com.sun.org.apache.bcel.internal.generic.RETURN
import jdk.nashorn.internal.parser.TokenType
import org.springframework.security.oauth2.provider.token.TokenStore
import java.time.Instant
import java.util.*
import java.util.stream.Collectors

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 18:00
 * @Description:
 */

class OAuth2TokenIntrospectionParser(private val tokenStore: TokenStore) : ITokenIntrospectionParser {

    override fun parse(token: String): TokenIntrospectionResponse {
        if (token.isBlank()) {
            return TokenIntrospectionErrorResponse(BearerTokenError.MISSING_TOKEN)
        }

        val accessToken = this.tokenStore.readAccessToken(token);
        val attributes = mutableMapOf<String, Any>()
        if (accessToken == null) {
            TokenIntrospectionErrorResponse(BearerTokenError.MISSING_TOKEN)
        }

        if (accessToken.isExpired) {
            return TokenIntrospectionErrorResponse(BearerTokenError.INVALID_TOKEN)
        }

        val authentication = tokenStore.readAuthentication(token)

        @Suppress("UNCHECKED_CAST")
        val details = authentication.details as? Map<String, Any>

        return TokenIntrospectionSuccessResponse.Builder(true)
                .expirationTime(Date.from(Instant.ofEpochMilli(accessToken.expiration.time)))
                .scope(Scope.parse(accessToken.scope))
                .apply {
                    if (accessToken.tokenType.isBlank()){
                        this.tokenType(AccessTokenType.UNKNOWN)
                    }else{
                        this.tokenType(AccessTokenType(accessToken.tokenType))
                    }
                }
                .subject(Subject(authentication.name))
                .apply {
                    details?.forEach { (key, _) ->
                        copyAttributesTo(details, key, attributes)
                    }
                }.build()
    }
}