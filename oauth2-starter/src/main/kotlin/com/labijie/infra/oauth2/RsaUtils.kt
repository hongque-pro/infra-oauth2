package com.labijie.infra.oauth2

import org.springframework.util.Base64Utils
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
object RsaUtils {

    fun getPublicKey(key: String): PublicKey {
        val keyBytes: ByteArray = Base64Utils.decodeFromString(key)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec)
    }


    fun getPrivateKey(key: String): PrivateKey {
        val keyBytes: ByteArray = Base64Utils.decodeFromString(key)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec)
    }
}
