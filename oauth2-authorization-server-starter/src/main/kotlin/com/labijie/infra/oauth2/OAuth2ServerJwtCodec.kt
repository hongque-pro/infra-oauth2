package com.labijie.infra.oauth2

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration

class OAuth2ServerJwtCodec(jwkSource: JWKSource<SecurityContext>) : IOAuth2ServerJwtCodec {
    private val decoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    private val encoder = NimbusJwtEncoder(jwkSource)

    @Throws(JwtException::class)
    override fun decode(token: String): Jwt {
        return decoder.decode(token)
    }


    @Throws(JwtEncodingException::class)
    override fun encode(headers: JwsHeader, claims: JwtClaimsSet): Jwt {
        return encoder.encode(JwtEncoderParameters.from(headers, claims))
    }

    override fun jwtDecoder(): JwtDecoder = decoder
    override fun jwtEncoder(): JwtEncoder = encoder
}