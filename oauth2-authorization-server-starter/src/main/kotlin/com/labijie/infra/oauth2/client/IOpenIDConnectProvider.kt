package com.labijie.infra.oauth2.client

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
interface IOpenIDConnectProvider {
    val providerName: String
    val decoder: OpenIdJwtDecoder
    val converter: IOidcLoginUserInfoConverter
}