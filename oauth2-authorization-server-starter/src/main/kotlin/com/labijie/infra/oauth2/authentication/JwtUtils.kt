package com.labijie.infra.oauth2.authentication

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.util.StringUtils
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*


object JwtUtils {
    fun headers(): JwsHeader.Builder {
        return JwsHeader.with(SignatureAlgorithm.RS256)
    }

    fun accessTokenClaims(
        issuer: String,
        registeredClient: RegisteredClient,
        subject: String?,
        authorizedScopes: Set<String>?
    ): JwtClaimsSet.Builder {
        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(registeredClient.tokenSettings.accessTokenTimeToLive)

        // @formatter:off
        val claimsBuilder = JwtClaimsSet.builder()
//        if (StringUtils.hasText(issuer)) {
//            claimsBuilder.issuer(issuer)
//        }
        claimsBuilder
            .issuer(issuer)
            .subject(subject)
            .audience(Collections.singletonList(registeredClient.clientId))
            .issuedAt(issuedAt)
            .expiresAt(expiresAt)
            .notBefore(issuedAt)
        if (!authorizedScopes.isNullOrEmpty()) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, authorizedScopes)
        }
        // @formatter:on
        return claimsBuilder
    }

    fun idTokenClaims(
        issuer: String,
        registeredClient: RegisteredClient,
        subject: String?,
        nonce: String?
    ): JwtClaimsSet.Builder {
        val issuedAt = Instant.now()
        // TODO Allow configuration for ID Token time-to-live
        val expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES)

        // @formatter:off
        val claimsBuilder = JwtClaimsSet.builder()

        claimsBuilder
            .issuer(issuer)
            .subject(subject)
            .audience(Collections.singletonList(registeredClient.clientId))
            .issuedAt(issuedAt)
            .expiresAt(expiresAt)
            .claim(IdTokenClaimNames.AZP, registeredClient.clientId)
        if (StringUtils.hasText(nonce)) {
            claimsBuilder.claim(IdTokenClaimNames.NONCE, nonce)
        }
        // TODO Add 'auth_time' claim
        // @formatter:on
        return claimsBuilder
    }
}