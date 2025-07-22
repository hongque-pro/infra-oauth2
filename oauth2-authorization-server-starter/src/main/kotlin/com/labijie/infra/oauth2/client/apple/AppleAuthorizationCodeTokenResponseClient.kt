package com.labijie.infra.oauth2.client.apple

import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.client.DefaultAuthorizationCodeTokenResponseClientClient
import com.labijie.infra.oauth2.client.ICustomAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.OAuth2ClientBuilders
import com.labijie.infra.oauth2.client.configuration.AppleOAuth2ClientRegistrationProperties
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import java.security.interfaces.RSAPrivateKey
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

            val scopes = if(clientRegistration.scopes.isEmpty()) setOf("email", "name") else clientRegistration.scopes

            val updatedRegistration = OAuth2ClientBuilders.apple(clientRegistration.clientId)
                .apply {
                    if(clientRegistration.scopes.isNotEmpty()) {
                        scope(scopes)
                    }
                }
                .clientName(clientRegistration.clientName)
                .clientSecret(generateClientSecret(clientRegistration))
                .build()

            val updatedRequest = OAuth2AuthorizationCodeGrantRequest(updatedRegistration, request.authorizationExchange)
            return DefaultAuthorizationCodeTokenResponseClientClient.getTokenResponse(updatedRequest)
        }

        return DefaultAuthorizationCodeTokenResponseClientClient.getTokenResponse(request)
    }

    fun loadPrivateKeyFromPKCS8(): RSAPrivateKey {
        val privateKey =
            OAuth2Utils.loadContent(properties.privateRsaKey, RsaUtils::getPrivateKey)
                ?: throw IllegalArgumentException("${AppleOAuth2ClientRegistrationProperties.PRIVATE_KEY_PROPERTY_PATH} is an invalid private rsa key.")
        return privateKey
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

        val privateKey = loadPrivateKeyFromPKCS8()

        val signedJWT = SignedJWT(header, claims)
        val signer = RSASSASigner(privateKey)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }
}