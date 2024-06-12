/**
 * @author Anders Xiao
 * @date 2024-06-12
 */
package com.labijie.infra.oauth2.component

import com.nimbusds.jose.jwk.RSAKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey


interface IOAuth2ServerRSAKeyPair {
    fun get(): RSAKey

    fun getPrivateKey(): RSAPrivateKey

    fun getPublicKey(): RSAPublicKey

    fun isDefaultKeys(): Boolean {

        get().toRSAPrivateKey()
        return false
    }
}