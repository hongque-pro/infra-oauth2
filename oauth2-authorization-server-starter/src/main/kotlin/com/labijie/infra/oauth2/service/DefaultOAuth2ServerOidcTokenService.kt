package com.labijie.infra.oauth2.service

import com.labijie.infra.oauth2.OAuth2ServerUtils.getIssuerOrDefault
import com.labijie.infra.oauth2.OAuth2Utils.toClaimSet
import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.StandardOidcUser.Companion.toAttributes
import com.labijie.infra.oauth2.client.OAuth2ClientProviderNames
import com.labijie.infra.oauth2.client.provider.apple.AppleOneTimeIdentifier
import com.labijie.infra.oauth2.client.provider.apple.IAppleIdOneTimeStore
import com.labijie.infra.oauth2.component.IOAuth2ServerRSAKeyPair
import com.labijie.infra.oauth2.exception.InvalidIdTokenException
import com.labijie.infra.utils.ifNullOrBlank
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.getBeanProvider
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
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
    private val serverKeyPair: IOAuth2ServerRSAKeyPair,
    private val settings: AuthorizationServerSettings) : IOAuth2ServerOidcTokenService, ApplicationContextAware {

    private var applicationContext: ApplicationContext? = null


    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger("com.labijie.infra.oauth2.service.OAuth2ServerOidcTokenService")
        }
    }

    private val appIdOneTimeStore by lazy {
        applicationContext?.getBeanProvider<IAppleIdOneTimeStore>()?.ifAvailable
    }

    override fun encode(
        user: StandardOidcUser,
        expiration: Duration,
        clientId: String?,
    ): String {
        val exp = Instant.now().plusMillis(expiration.toMillis())
        val claims = JWTClaimsSet.Builder()
            .subject(user.userId)
            .issuer(settings.getIssuerOrDefault())
            .audience(clientId.ifNullOrBlank { user.provider })
            .apply {
                user.toAttributes().forEach {
                    claim(it.key, it.value)
                }
            }
            .expirationTime(Date.from(exp)) // 1 hour
            .issueTime(Date())
            .build()

        if(user.provider.equals(OAuth2ClientProviderNames.APPLE, ignoreCase = true) && user.userId.isNotBlank() && !user.email.isNullOrBlank()) {
            appIdOneTimeStore?.let { store ->
                if (store.get(user.userId) == null) {
                    store.save(user.userId, AppleOneTimeIdentifier(user.username.orEmpty(), user.email.orEmpty()))
                    logger.info("Apple id one-time information saved: name=${user.username}, email=${user.email}")
                }
            }
        }

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

        if(issuer != settings.getIssuerOrDefault()) {
            throw InvalidIdTokenException("Invalid issuer claim")
        }

        val user = StandardOidcUser.createFromClaimSet(claims.toClaimSet())

        if(user.provider.equals(OAuth2ClientProviderNames.APPLE, ignoreCase = true) && user.userId.isNotBlank() && (user.email.isNullOrBlank() || user.username.isNullOrBlank())) {
            appIdOneTimeStore?.let { store ->
                if (store.get(user.userId) == null) {
                   store.get(user.userId)?.let {
                       appleId->
                       if(user.username.isNullOrBlank()) {
                           user.username = appleId.name
                       }
                       if(user.username.isNullOrBlank()) {
                           user.username = appleId.name
                       }
                       logger.info("Apple id one-time information loaded: name=${appleId.name}, email=${appleId.email}")
                    }
                }
            }
        }

        return user
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }
}