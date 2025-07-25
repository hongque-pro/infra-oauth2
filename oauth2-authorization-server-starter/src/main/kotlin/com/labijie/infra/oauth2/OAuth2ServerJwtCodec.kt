package com.labijie.infra.oauth2

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration

class OAuth2ServerJwtCodec(
    private val issuerUri: String?,
    jwkSource: JWKSource<SecurityContext>) : IOAuth2ServerJwtCodec {
    private val decoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource).apply {
        if(this is NimbusJwtDecoder) {
            val validator = if(!issuerUri.isNullOrBlank()) {
                createOAuth2TokenValidator(issuerUri)
            }else null

            validator?.let {
                this.setJwtValidator(validator)
            }
        }
    }
    private val encoder = NimbusJwtEncoder(jwkSource)


    private fun createOAuth2TokenValidator(issuerUri: String?): OAuth2TokenValidator<Jwt> {
        val validators = mutableListOf<OAuth2TokenValidator<Jwt>>()
        issuerUri?.let {
            validators.add(JwtIssuerValidator(issuerUri))
        }

        return DelegatingOAuth2TokenValidator(*validators.toTypedArray())
    }

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