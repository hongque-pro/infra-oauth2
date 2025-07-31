package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.client.extension.IOpenIDConnectProvider

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
interface IOpenIDConnectService {

    fun allProviders() : Set<String>

    fun hasProvider(provider: String): Boolean

    fun addProvider(provider: IOpenIDConnectProvider)

    fun decodeToken(
        provider: String,
        jwt: String,
        authorizationCode: String? = null,
        nonce: String? = null,
        ignoreExpiration: Boolean = false,
    ): StandardOidcUser
}