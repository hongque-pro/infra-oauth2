package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.URIBasedJWKSetSource
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientTokenException
import com.labijie.infra.oauth2.getRSAKey
import com.labijie.infra.utils.ifNullOrBlank
import com.labijie.infra.utils.toLocalDateTime
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationCode
import com.nimbusds.openid.connect.sdk.claims.CodeHash
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.http.HttpMethod
import org.springframework.web.client.RestClient
import java.net.URI
import java.text.ParseException
import java.time.Duration
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.*

class OpenIdJwtDecoder(
    val providerName: String,
    private val issuer: String,
    private val jwkSource: JWKSource<SecurityContext>,
    private val audienceSet: Set<String> = emptySet(),
) {

    companion object {

        fun fromProvider(
            providerName: String,
            provider: OAuth2ClientProperties.Provider,
            audienceSet: Set<String>,
            ): OpenIdJwtDecoder {

            if(provider.jwkSetUri.isNullOrBlank()) {
                throw IllegalArgumentException("Provider jwkSetUri can not be empty for creating OpenIdJwtDecoder.")
            }

            if(provider.issuerUri.isNullOrBlank()) {
                throw IllegalArgumentException("Provider issuerUri can not be empty for creating OpenIdJwtDecoder.")
            }

            return fromUri(providerName, URI(provider.jwkSetUri.orEmpty()), provider.issuerUri, audienceSet)
        }

        fun fromUri(
            provider: String,
            jwkSetURI: URI,
            issuer: String,
            audienceSet: Set<String>,
            resetClient: RestClient? = null,
            httpMethod: HttpMethod = HttpMethod.GET,
            cacheEnabled: Boolean = true,
            timeToLive: Duration = Duration.ofMinutes(5),
            cacheRefreshTimeout: Duration = Duration.ofSeconds(15),
        ): OpenIdJwtDecoder {
            val client = resetClient ?: RestClient.builder().build()
            val remoteSource = URIBasedJWKSetSource<SecurityContext>(client, jwkSetURI, httpMethod)
            val jwkSource = JWKSourceBuilder<SecurityContext>.create(remoteSource)
                .cache(
                    timeToLive.toMillis(),
                    cacheRefreshTimeout.toMillis()
                )
                .cache(cacheEnabled)
                .build()

            return OpenIdJwtDecoder(
                provider,
                issuer,
                jwkSource,
                audienceSet
            )
        }
    }

    private val logger by lazy { LoggerFactory.getLogger(OpenIdJwtDecoder::class.java) }


    fun decode(
        jwt: String,
        authorizationCode: String? = null,
        nonce: String? = null,
        ignoreExpiration: Boolean = false
    ): SignedJWT {
        if (jwt.isBlank()) {
            throw InvalidOAuth2ClientTokenException(providerName, "Id token can not be empty")
        }

        val signedJWT = try {
            SignedJWT.parse(jwt)
        } catch (_: ParseException) {
            throw InvalidOAuth2ClientTokenException(providerName, "Failed to parse JWT token")
        }
        val kid =
            signedJWT.header.keyID ?: throw InvalidOAuth2ClientTokenException(
                providerName,
                "Missing key ID in id token"
            )

        val key = jwkSource.getRSAKey(kid)
            ?: throw InvalidOAuth2ClientTokenException(providerName, "Missing key with id '${kid}'")

        val publicKey = try {
            key.toRSAPublicKey()
        } catch (e: JOSEException) {
            logger.error("Failed to convert RSAKey to public key", e)
            throw InvalidOAuth2ClientTokenException(providerName, "Failed to convert RSAKey to public key.")
        }

        val verifier = RSASSAVerifier(publicKey)

        val valid = signedJWT.verify(verifier)
        if (!valid) {
            throw InvalidOAuth2ClientTokenException(providerName, "Invalid JWT signature.")
        }

        val claims = signedJWT.jwtClaimsSet

        if (!ignoreExpiration && !claims.expirationTime.after(Date())) {
            val localDateTime = claims.expirationTime.toInstant().toLocalDateTime(ZoneId.systemDefault())
            val timeString = localDateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
            throw InvalidOAuth2ClientTokenException(providerName, "Apple id token expired at: ${timeString}).")
        }

        if (claims.subject.isNullOrBlank()) {
            throw InvalidOAuth2ClientTokenException(providerName, "Subject is empty in id token.")
        }

        val idTokenClaimsSet = try {
            IDTokenClaimsSet(claims)
        } catch (_: com.nimbusds.oauth2.sdk.ParseException) {
            // Claims set must be verified at this point
            null
        }

        if (idTokenClaimsSet != null) {
            if (idTokenClaimsSet.codeHash != null && !authorizationCode.isNullOrBlank()) {
                val alg = signedJWT.header.algorithm
                val sh = CodeHash.computeValue(AuthorizationCode(authorizationCode), alg, null)
                if (sh != idTokenClaimsSet.codeHash.value) {
                    throw InvalidOAuth2ClientTokenException(providerName, "Invalid c_hash in id token.")
                }
            }

            if (idTokenClaimsSet.nonce != null && !nonce.isNullOrBlank()) {
                if (idTokenClaimsSet.nonce.value != nonce) {
                    throw InvalidOAuth2ClientTokenException(providerName, "Nonce is incorrect.")
                }
            }
        }


        if (!claims.issuer.equals(issuer, ignoreCase = true)) {
            throw InvalidOAuth2ClientTokenException(
                providerName,
                "Invalid issuer in oidc id token (expected: ${issuer}, got: ${claims.issuer.ifNullOrBlank { "<empty>" }})."
            )
        }

        if (audienceSet.isNotEmpty() && !claims.audience.isNotEmpty() && !claims.audience.any { audienceSet.contains(it) }) {
            throw InvalidOAuth2ClientTokenException(
                providerName,
                "Invalid audience (aud) in oidc id token (aud: ${claims.audience.joinToString(", ")})."
            )
        }

        return signedJWT
    }

}