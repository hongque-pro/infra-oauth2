/**
 * @author Anders Xiao
 * @date 2024-06-12
 */
package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.component.IOAuth2ServerRSAKeyPair
import com.labijie.infra.oauth2.component.IOAuth2ServerSecretsStore
import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


internal class OAuth2ServerRSAKeyPair(
    private val serverProperties: OAuth2ServerProperties,
    private val secretsStore: IOAuth2ServerSecretsStore?
) : IOAuth2ServerRSAKeyPair {

    private var useDefaultRsaKey =
        serverProperties.token.jwt.rsa.privateKey.isBlank() || serverProperties.token.jwt.rsa.publicKey.isBlank()

    private var keyId = UUID.randomUUID().toString()

    override fun isDefaultKeys(): Boolean {
        return useDefaultRsaKey
    }

    private val keySet: RSAKeySet by lazy {
        val kp = if (secretsStore != null) {
            val pub = RsaUtils.getPublicKey(secretsStore.getRsaPublicKey(serverProperties))
            val pri = RsaUtils.getPrivateKey(secretsStore.getRsaPrivateKey(serverProperties))
            useDefaultRsaKey = false
            KeyPair(pub, pri)
        } else if (useDefaultRsaKey) {
            serverProperties.token.jwt.rsa.privateKey =
                Base64.getEncoder().encodeToString(RsaUtils.defaultKeyPair.private.encoded)
            serverProperties.token.jwt.rsa.publicKey =
                Base64.getEncoder().encodeToString(RsaUtils.defaultKeyPair.public.encoded)
            RsaUtils.defaultKeyPair
        } else {
            val privateKey =
                OAuth2Utils.loadContent(serverProperties.token.jwt.rsa.privateKey, RsaUtils::getPrivateKey)
                    ?: throw IllegalArgumentException("${OAuth2ServerProperties.PRIVATE_KEY_PROPERTY_PATH} is an invalid")
            val publicKey =
                OAuth2Utils.loadContent(serverProperties.token.jwt.rsa.publicKey, RsaUtils::getPublicKey)
                    ?: throw IllegalArgumentException("${OAuth2ServerProperties.PUBLIC_KEY_PROPERTY_PATH} is an invalid")
            KeyPair(publicKey, privateKey)
        }
        val publicKey: RSAPublicKey = kp.public as RSAPublicKey
        val privateKey: RSAPrivateKey = kp.private as RSAPrivateKey

        RSAKeySet(keyId, privateKey, publicKey)
    }

    private class RSAKeySet(keyId: String, val privateKey: RSAPrivateKey, val publicKey: RSAPublicKey) {
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(keyId)
            .build()
    }


    override fun getPrivateKey(): RSAPrivateKey {
        return keySet.privateKey
    }

    override fun get(): RSAKey {
        return keySet.rsaKey
    }


    override fun getPublicKey(): RSAPublicKey {
        return keySet.publicKey
    }

}