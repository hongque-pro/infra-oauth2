package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientTokenException
import com.labijie.infra.utils.ifNullOrBlank
import com.labijie.infra.utils.toLocalDateTime
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationCode
import com.nimbusds.openid.connect.sdk.claims.CodeHash
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.client.RestClient
import java.net.URI
import java.text.ParseException
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.*
import java.util.concurrent.atomic.AtomicReference

class OpenIdJwtDecoder(
    private val clientName: String,
    private val issuer: String,
    private val jwkURI: URI,
    private val resetClient: RestClient? = null,
) {


    companion object {
        fun apple(resetClient: RestClient? = null): OpenIdJwtDecoder {
            return OpenIdJwtDecoder(
                "Apple",
                "https://appleid.apple.com",
                URI("https://appleid.apple.com/auth/keys"),
                resetClient
            )
        }
    }

    private val logger by lazy { LoggerFactory.getLogger(OpenIdJwtDecoder::class.java) }


    // 公钥缓存
    private val cachedKeys = AtomicReference<JWKSet?>()
    private var lastFetchTime: Long = 0
    private val cacheDurationMillis = 60 * 60 * 1000L // 1 小时

    private val client by lazy {
        resetClient ?: RestClient.builder().build()
    }

    private fun getAppleAuthKeys(): JWKSet {
        val now = System.currentTimeMillis()

        if (cachedKeys.get() == null || now - lastFetchTime > cacheDurationMillis) {
            val response = client.get().uri(jwkURI)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .toEntity(String::class.java)

            if (!response.statusCode.is2xxSuccessful) {
                throw InvalidOAuth2ClientTokenException(
                    clientName,
                    "Failed to fetch Apple public auth keys, http status: ${response.statusCode}\n request url: $jwkURI"
                )
            }

            val jwkSet =
                JWKSet.parse(
                    response.body ?: throw InvalidOAuth2ClientTokenException(
                        clientName,
                        "Empty body in Apple public keys"
                    )
                )
            cachedKeys.set(jwkSet)
            lastFetchTime = now
        }
        return cachedKeys.get()!!
    }

    fun decode(
        jwt: String,
        authorizationCode: String? = null,
        nonce: String? = null,
        ignoreExpiration: Boolean = false
    ): SignedJWT {
        if (jwt.isBlank()) {
            throw InvalidOAuth2ClientTokenException(clientName, "Id token can not be empty")
        }

        val signedJWT = try {
            SignedJWT.parse(jwt)
        } catch (_: ParseException) {
            throw InvalidOAuth2ClientTokenException(clientName, "Failed to parse JWT token")
        }
        val kid =
            signedJWT.header.keyID ?: throw InvalidOAuth2ClientTokenException(clientName, "Missing key ID in id token")

        val key = getAppleAuthKeys().getKeyByKeyId(kid) as? RSAKey
            ?: throw InvalidOAuth2ClientTokenException(clientName, "Missing key with id '${kid}'")

        val publicKey = try {
            key.toRSAPublicKey()
        } catch (e: JOSEException) {
            logger.error("Failed to convert RSAKey to public key", e)
            throw InvalidOAuth2ClientTokenException(clientName, "Failed to convert RSAKey to public key.")
        }

        val verifier = RSASSAVerifier(publicKey)

        val valid = signedJWT.verify(verifier)
        if (!valid) {
            throw InvalidOAuth2ClientTokenException(clientName, "Invalid JWT signature.")
        }

        val claims = signedJWT.jwtClaimsSet

        if (!ignoreExpiration && !claims.expirationTime.after(Date())) {
            val localDateTime = claims.expirationTime.toInstant().toLocalDateTime(ZoneId.systemDefault())
            val timeString = localDateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
            throw InvalidOAuth2ClientTokenException(clientName, "Apple id token expired at: ${timeString}).")
        }

        if (claims.subject.isNullOrBlank()) {
            throw InvalidOAuth2ClientTokenException(clientName, "Subject is empty in id token.")
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
                    throw InvalidOAuth2ClientTokenException(clientName, "Invalid c_hash in id token.")
                }
            }

            if (idTokenClaimsSet.nonce != null && !nonce.isNullOrBlank()) {
                if (idTokenClaimsSet.nonce.value != nonce) {
                    throw InvalidOAuth2ClientTokenException(clientName, "Nonce is incorrect.")
                }
            }
        }


        if (!claims.issuer.equals(issuer, ignoreCase = true)) {
            throw InvalidOAuth2ClientTokenException(
                clientName,
                "Invalid issuer in apple id token (expected: https://appleid.apple.com, got: ${claims.issuer.ifNullOrBlank { "<empty>" }})."
            )
        }

        return signedJWT
    }

}