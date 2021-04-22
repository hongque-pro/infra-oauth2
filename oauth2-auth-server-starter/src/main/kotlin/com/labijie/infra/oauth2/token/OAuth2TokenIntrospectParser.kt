package com.labijie.infra.oauth2.token

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.ITokenIntrospectParser
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse
import com.nimbusds.oauth2.sdk.id.Audience
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.BearerTokenError
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.AccessTokenConverter
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import java.time.Instant
import java.util.*

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 18:00
 * @Description:
 */

class OAuth2TokenIntrospectParser(private val tokenStore: TokenStore) : ITokenIntrospectParser {

    companion object {
        private const val ROLE_PREFIX = "ROLE_"
        private const val SCOPE_PREFIX = "SCOPE_"
    }

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

        val authentication = tokenStore.readAuthentication(token)

        return TokenIntrospectionSuccessResponse.Builder(true)
                .expirationTime(accessToken.expiration)
                .scope(Scope.parse(accessToken.scope))
                .apply {
                    if (accessToken.tokenType.isBlank()) {
                        this.tokenType(AccessTokenType.UNKNOWN)
                    } else {
                        this.tokenType(AccessTokenType(accessToken.tokenType))
                    }

                    authentication?.oAuth2Request?.resourceIds?.also {
                        this.audience(it.map { item-> Audience(item)  })
                    }

                    val authorities = mutableSetOf<String>()
                    if (accessToken.additionalInformation.containsKey(Constants.CLAIM_ROLES)) {
                        val roles = accessToken.additionalInformation[Constants.CLAIM_ROLES] as? Iterable<*>
                        roles?.forEach {
                            if(it != null){
                                authorities.add("$ROLE_PREFIX$it")
                            }
                        }
                    }

                    if (accessToken.additionalInformation.containsKey(Constants.CLAIM_AUTHORITIES)) {
                        val roles = accessToken.additionalInformation[Constants.CLAIM_AUTHORITIES] as? Iterable<*>
                        roles?.forEach {
                            if(it != null){
                                authorities.add(it.toString())
                            }
                        }
                    }

                    this.parameter(Constants.CLAIM_AUTHORITIES, authorities)
                }
                .apply {
                    accessToken.additionalInformation.filter {
                        it.key != Constants.CLAIM_AUTHORITIES && it.key != Constants.CLAIM_ROLES
                    }.forEach { (key, v) ->
                        this.parameter(key, v)
                    }
                }.build()
    }
}