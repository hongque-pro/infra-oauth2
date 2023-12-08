package com.labijie.infra.oauth2.component

/**
 * @author Anders Xiao
 * @date 2023-12-08
 */
interface IOAuth2ServerSecretsStore {
    /**
     * Get rsa private key (pkcs8 pem content)
     */
     fun getRsaPrivateKey() : String

    /**
     * Get rsa public key (pkcs8 pem content)
     */
    fun getRsaPublicKey() : String
}