package com.labijie.infra.oauth2.component

import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.utils.logger
import com.nimbusds.jose.jwk.RSAKey
import org.bouncycastle.jcajce.provider.asymmetric.RSA
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.*

/**
 * @author Anders Xiao
 * @date 2024-06-12
 */
class DefaultOAuth2ServerRSAKeyPair(
    private val serverProperties: OAuth2ServerProperties,
    private val secretsStore: IOAuth2ServerSecretsStore? = null
) : IOAuth2ServerRSAKeyPair {

    private val rsaConfigured by lazy {
        if(serverProperties.token.jwt.rsa.privateKey.isBlank()) {
            logger.warn("RSA private key is missing for oauth2 server.")
            false
        }else {
            true
        }
    }


    private var keyId = UUID.randomUUID().toString()

    private fun loadPublicKeyFromPrivateKey(privateKey: RSAPrivateKey): RSAPublicKey? {
        return try {
            if (privateKey is RSAPrivateCrtKey) {
                val keyFactory = KeyFactory.getInstance("RSA")
                val spec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
                keyFactory.generatePublic(spec) as? RSAPublicKey
            }else null
        }
        catch (e: Throwable) {
            logger.warn("Could not generate public key from rsa private key for oauth2 server", e)
            null
        }
    }

    override fun isDefaultKeys(): Boolean {
        return rsaConfigured || secretsStore != null
    }

    private val keySet: RSAKeySet by lazy {



        val kp = if (secretsStore != null) {
            val pub = RsaUtils.getPublicKey(secretsStore.getRsaPublicKey(serverProperties))
            val pri = RsaUtils.getPrivateKey(secretsStore.getRsaPrivateKey(serverProperties))
            KeyPair(pub, pri)
        } else if (!rsaConfigured) {
            serverProperties.token.jwt.rsa.privateKey =
                Base64.getEncoder().encodeToString(RsaUtils.defaultKeyPair.private.encoded)
            serverProperties.token.jwt.rsa.publicKey =
                Base64.getEncoder().encodeToString(RsaUtils.defaultKeyPair.public.encoded)
            RsaUtils.defaultKeyPair
        } else {
            val privateKey =
                OAuth2Utils.loadContent(serverProperties.token.jwt.rsa.privateKey, RsaUtils::getPrivateKey)
                    ?: throw IllegalArgumentException("${OAuth2ServerProperties.Companion.PRIVATE_KEY_PROPERTY_PATH} is an invalid private rsa key.")
            val publicKey = if(serverProperties.token.jwt.rsa.publicKey.isBlank()) {
                loadPublicKeyFromPrivateKey(privateKey)
            }else {
                OAuth2Utils.loadContent(serverProperties.token.jwt.rsa.publicKey, RsaUtils::getPublicKey)
                    ?: throw IllegalArgumentException("${OAuth2ServerProperties.Companion.PUBLIC_KEY_PROPERTY_PATH} is an invalid public rsa key.")
            }
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