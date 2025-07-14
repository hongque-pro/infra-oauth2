package com.labijie.infra.oauth2.resource.oauth2.apple

import com.labijie.infra.oauth2.resource.DefaultAuthorizationCodeTokenResponseClientClient
import com.labijie.infra.oauth2.resource.configuration.AppleOAuth2ClientRegistrationProperties
import com.labijie.infra.oauth2.resource.oauth2.ICustomAuthorizationCodeTokenResponseClient
import com.labijie.infra.security.RsaKeyHelper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.*

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
class AppleAuthorizationCodeTokenResponseClient(
    private val properties: AppleOAuth2ClientRegistrationProperties
) : ICustomAuthorizationCodeTokenResponseClient {
    override fun isSupported(client: ClientRegistration): Boolean {
        return client.registrationId.lowercase() == "apple"
    }

    override fun getTokenResponse(request: OAuth2AuthorizationCodeGrantRequest): OAuth2AccessTokenResponse {

        val clientRegistration = request.clientRegistration

        if (clientRegistration.registrationId.lowercase() == "apple") {

            val updatedRegistration = ClientRegistration.withClientRegistration(clientRegistration)
                .clientSecret(generateClientSecret(clientRegistration))
                .build()

            val updatedRequest = OAuth2AuthorizationCodeGrantRequest(updatedRegistration, request.authorizationExchange)
            return DefaultAuthorizationCodeTokenResponseClientClient.getTokenResponse(updatedRequest)
        }

        return DefaultAuthorizationCodeTokenResponseClientClient.getTokenResponse(request)
    }

    fun loadPrivateKeyFromPKCS8(pem: String): RSAPrivateKey {
        val keyBytes: ByteArray = RsaKeyHelper.extractRsaPem(properties.privateRsaKey)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
    }


    fun generateClientSecret(client: ClientRegistration): String {

        client.providerDetails.configurationMetadata

        val now = Instant.now()
        val exp = now.plusSeconds(properties.secretValiditySeconds.toLong())

        val claims = JWTClaimsSet.Builder()
            .issuer(properties.teamId)
            .subject(client.clientId)
            .audience("https://appleid.apple.com")
            .issueTime(Date.from(now))
            .expirationTime(Date.from(exp))
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(properties.keyId)
            .type(JOSEObjectType.JWT)
            .build()

        val privateKey = loadPrivateKeyFromPKCS8(properties.privateRsaKey)

        val signedJWT = SignedJWT(header, claims)
        val signer = RSASSASigner(privateKey)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }
}