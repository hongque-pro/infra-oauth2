package com.labijie.infra.oauth2.resource.oauth2.apple

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.getBean
import org.springframework.beans.factory.getBeanProvider
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.http.MediaType
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.web.client.RestClient
import java.net.URI
import java.text.ParseException
import java.util.*
import java.util.concurrent.atomic.AtomicReference

class AppleJwtDecoder(
): ApplicationContextAware {
    private val logger by lazy { LoggerFactory.getLogger(AppleJwtDecoder::class.java) }

    private var applicationContext: ApplicationContext? = null


    private val restClientBuilder by lazy {
        applicationContext?.getBeanProvider<RestClient.Builder>()?.ifAvailable ?: RestClient.builder()
    }

    private val client by lazy {
        val context = applicationContext ?:  throw RuntimeException("ApplicationContext is null")
        val clientProperties = context.getBean<ClientRegistrationRepository>()
        val client = clientProperties.findByRegistrationId("apple") ?: throw RuntimeException("Apple oauth2 client has not been registered (name: apple)")
        client
    }
    // 公钥缓存
    private val cachedKeys = AtomicReference<JWKSet?>()
    private var lastFetchTime: Long = 0
    private val cacheDurationMillis = 60 * 60 * 1000L // 1 小时

    private fun getAppleAuthKeys(): JWKSet {
        val now = System.currentTimeMillis()
        val client = restClientBuilder.build()

        if (cachedKeys.get() == null || now - lastFetchTime > cacheDurationMillis) {
            logger.info("Fetching Apple public keys from https://appleid.apple.com/auth/keys")
            val url = URI.create("https://appleid.apple.com/auth/keys")
            val response = client.get().uri(url)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .toEntity(String::class.java)

            if (!response.statusCode.is2xxSuccessful) {
                throw RuntimeException("Failed to fetch Apple keys: ${response.statusCode}")
            }

            val jwkSet = JWKSet.parse(response.body ?: throw RuntimeException("Apple keys body is empty"))
            cachedKeys.set(jwkSet)
            lastFetchTime = now
        }

        return cachedKeys.get()!!
    }

    /**
     * 验证 Apple 返回的 identityToken
     * @param jwt 前端传来的 identityToken
     * @return true 表示验证通过
     */
    fun decode(jwt: String, clientId: String?): SignedJWT {
        val signedJWT = try {
            SignedJWT.parse(jwt)
        }catch (ex: ParseException) {
            throw AppleAuthenticationException("Failed to parse JWT token")
        }
        val kid = signedJWT.header.keyID ?: throw AppleAuthenticationException("Missing key ID")

        val key = getAppleAuthKeys().getKeyByKeyId(kid) as? RSAKey ?: throw AppleAuthenticationException("Missing key with id '${kid}'")

        val publicKey = try {
            key.toRSAPublicKey()
        } catch (e: JOSEException) {
            logger.error("Failed to convert RSAKey to public key", e)
            throw AppleAuthenticationException("Failed to convert RSAKey to public key.")
        }

        val verifier = RSASSAVerifier(publicKey)

        val valid = signedJWT.verify(verifier)
        if (!valid) {
            throw AppleAuthenticationException("Invalid JWT signature")
        }

        val claims = signedJWT.jwtClaimsSet

        val signInClientId = clientId ?: client.clientId

        // 校验 iss、aud、exp、sub
        val now = Date()
        val ok = claims.issuer.equals("https://appleid.apple.com", ignoreCase = true)
                && claims.audience.contains(signInClientId)
                && claims.expirationTime.after(now)
                && !claims.subject.isNullOrBlank()

        if(!ok){
            throw AppleAuthenticationException("Invalid JWT token")
        }
        return signedJWT
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }
}
