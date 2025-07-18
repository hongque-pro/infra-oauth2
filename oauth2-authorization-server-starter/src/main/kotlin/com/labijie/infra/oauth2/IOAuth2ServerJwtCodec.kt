package com.labijie.infra.oauth2

import org.springframework.security.oauth2.jwt.*

interface IOAuth2ServerJwtCodec {
    @Throws(JwtException::class)
    fun decode(token: String): Jwt


    @Throws(JwtEncodingException::class)
    fun encode(headers: JwsHeader, claims: JwtClaimsSet): Jwt

    fun jwtDecoder(): JwtDecoder
    fun jwtEncoder(): JwtEncoder
}