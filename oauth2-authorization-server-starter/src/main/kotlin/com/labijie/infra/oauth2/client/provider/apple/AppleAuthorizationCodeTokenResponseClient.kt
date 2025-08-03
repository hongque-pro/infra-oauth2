package com.labijie.infra.oauth2.client.provider.apple

import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.client.DefaultAuthorizationCodeTokenResponseClientClient
import com.labijie.infra.oauth2.client.extension.ICustomAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.OAuth2ClientProviderNames
import com.labijie.infra.oauth2.client.configuration.AppleOAuth2ClientRegistrationProperties
import com.labijie.infra.oauth2.client.findProvider
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.bouncycastle.util.io.pem.PemReader
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
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
    private val oauth2ClientProperties: OAuth2ClientProperties,
    private val properties: AppleOAuth2ClientRegistrationProperties
) : ICustomAuthorizationCodeTokenResponseClient {

    override fun isSupported(client: ClientRegistration): Boolean {
        return client.findProvider(oauth2ClientProperties).equals(OAuth2ClientProviderNames.APPLE, ignoreCase = true)
    }

    override fun getTokenResponse(request: OAuth2AuthorizationCodeGrantRequest): OAuth2AccessTokenResponse {

        val clientRegistration = request.clientRegistration

        val updatedRegistration = ClientRegistration.withClientRegistration(clientRegistration)
            .apply {
                if (clientRegistration.scopes.isNullOrEmpty()) {
                    this.scope(setOf("email", "name"))
                }
            }
            .clientSecret(generateClientSecret(clientRegistration))
            .build()

        val updatedRequest = OAuth2AuthorizationCodeGrantRequest(updatedRegistration, request.authorizationExchange)
        val token = DefaultAuthorizationCodeTokenResponseClientClient.getTokenResponse(updatedRequest)
        return token
    }

    fun loadPrivateKeyFromPKCS8(): ECPrivateKey? {

        if(properties.privateRsaKey.isBlank()) {
            return null
        }

        val pem =
            OAuth2Utils.loadContent(properties.privateRsaKey) { pem ->
                val bytes = pem.toByteArray(Charsets.UTF_8)
                bytes.inputStream().use { inputStream ->
                    InputStreamReader(inputStream).use { keyReader ->
                        PemReader(keyReader).use { pemReader ->
                            pemReader.readPemObject()
                        }
                    }
                }
            }

        return pem?.let {
            val keySpec = PKCS8EncodedKeySpec(pem.content)
            val keyFactory = KeyFactory.getInstance("EC")
            return keyFactory.generatePrivate(keySpec) as? ECPrivateKey
        }
    }


    fun generateClientSecret(client: ClientRegistration): String {

        //refer: https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret

        client.providerDetails.configurationMetadata

        val now = Instant.now()
        val exp = now.plusSeconds(properties.secretValidity.seconds.coerceAtLeast(1))



        val claims = JWTClaimsSet.Builder()
            .issuer(properties.teamId)
            .subject(client.clientId)
            .audience("https://appleid.apple.com")
            .issueTime(Date.from(now))
            .expirationTime(Date.from(exp))
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(properties.keyId)
            .type(JOSEObjectType.JWT)
            .build()

        val privateKey = loadPrivateKeyFromPKCS8()

        val signedJWT = SignedJWT(header, claims)

        val signer = ECDSASigner(privateKey)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }
}