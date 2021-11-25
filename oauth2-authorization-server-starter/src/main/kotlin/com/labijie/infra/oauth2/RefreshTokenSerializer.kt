package com.labijie.infra.oauth2

import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.jwt.*
import java.time.Duration
import java.time.Instant

object RefreshTokenSerializer{

    fun serialize(encoder: JwtEncoder, claims: JwtClaimsSet, tokenTimeToLive: Duration): OAuth2RefreshToken {
        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(tokenTimeToLive)
        val header = JoseHeader.builder().build()
        val value = encoder.encode(header, claims).tokenValue
        return OAuth2RefreshToken(value, expiresAt)
    }

    fun deserialize(decoder: JwtDecoder, tokenValue: String): OAuth2RefreshToken? {
        val jwt = decoder.decode(tokenValue)
        val nowSeconds = Instant.now().epochSecond

        if ((jwt.expiresAt?.epochSecond ?: nowSeconds) <= nowSeconds) {
            return null
        }
        return OAuth2RefreshToken(tokenValue, jwt.expiresAt)
    }
}