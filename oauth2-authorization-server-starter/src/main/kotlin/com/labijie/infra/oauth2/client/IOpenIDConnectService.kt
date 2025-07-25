package com.labijie.infra.oauth2.client

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
    ): OAuth2LoginUser
}