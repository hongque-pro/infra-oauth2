package com.labijie.infra.oauth2.component

import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties

/**
 * @author Anders Xiao
 * @date 2023-12-08
 */
interface IOAuth2ServerSecretsStore {
    /**
     * Get rsa private key (pkcs8 pem content)
     */
     fun getRsaPrivateKey(properties: OAuth2ServerProperties) : String

    /**
     * Get rsa public key (pkcs8 pem content)
     */
    fun getRsaPublicKey(properties: OAuth2ServerProperties) : String
}