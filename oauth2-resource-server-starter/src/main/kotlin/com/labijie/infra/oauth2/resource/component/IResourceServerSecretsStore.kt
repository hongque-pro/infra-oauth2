package com.labijie.infra.oauth2.resource.component

import com.labijie.infra.oauth2.resource.configuration.ResourceServerProperties

/**
 * @author Anders Xiao
 * @date 2023-12-08
 */
interface IResourceServerSecretsStore {

    /**
     * Get rsa public key (pkcs8 pem content)
     */
    fun getRsaPublicKey(properties: ResourceServerProperties) : String
}