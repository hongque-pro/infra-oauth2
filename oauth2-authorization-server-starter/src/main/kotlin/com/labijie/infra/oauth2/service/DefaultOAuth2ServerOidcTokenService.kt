package com.labijie.infra.oauth2.service

import com.labijie.infra.oauth2.OAuth2Utils.toClaimSet
import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.StandardOidcUser.Companion.toAttributes
import com.labijie.infra.oauth2.component.IOAuth2ServerRSAKeyPair
import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.oauth2.exception.InvalidIdTokenException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.time.Duration
import java.time.Instant
import java.util.*

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/31
 *
 */
class DefaultOAuth2ServerOidcTokenService(
    private val  serverKeyPair: IOAuth2ServerRSAKeyPair,
    private val serverProperties: OAuth2ServerProperties) : IOAuth2ServerOidcTokenService {

    override fun encode(
        user: StandardOidcUser,
        expiration: Duration
    ): String {
        val exp = Instant.now().plusMillis(expiration.toMillis())
        val claims = JWTClaimsSet.Builder()
            .subject(user.userId)
            .issuer(serverProperties.issuer?.toString())
            .audience("your-client-id")
            .apply {
                user.toAttributes().forEach {
                    claim(it.key, it.value)
                }
            }
            .expirationTime(Date.from(exp)) // 1 hour
            .issueTime(Date())
            .build()

        val header = JWSHeader(JWSAlgorithm.RS256)
        val signedJWT = SignedJWT(header, claims)
        val signer = RSASSASigner(serverKeyPair.getPrivateKey())
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

    override fun decode(idToken: String, ignoreExpiration: Boolean): StandardOidcUser {
        val signedJWT = SignedJWT.parse(idToken)

        // 验证签名
        val verifier = RSASSAVerifier(serverKeyPair.getPublicKey())
        if (!signedJWT.verify(verifier)) {
            throw InvalidIdTokenException("Invalid ID Token signature.")
        }

        val claims = signedJWT.jwtClaimsSet

        // 检查过期时间（除非指定忽略）
        if (!ignoreExpiration) {
            val exp = claims.expirationTime?.toInstant()
            if (exp != null && Instant.now().isAfter(exp)) {
                throw InvalidIdTokenException("ID Token has expired.")
            }
        }

        if(claims.subject.isNullOrBlank()) {
            throw InvalidIdTokenException("Missing subject claim")
        }

        val provider = claims.getStringClaim(StandardOidcUser.CLAIM_NAME_PROVIDER)
        if(provider.isNullOrBlank()) {
            throw InvalidIdTokenException("Missing provider claim")
        }

        val issuer = claims.issuer

        if(issuer != serverProperties.issuer?.toString()) {

        }

        return StandardOidcUser.createFromClaimSet(claims.toClaimSet())
    }
}