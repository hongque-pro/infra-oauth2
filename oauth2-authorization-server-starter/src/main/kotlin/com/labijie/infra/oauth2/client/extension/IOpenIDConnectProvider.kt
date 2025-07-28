package com.labijie.infra.oauth2.client.extension

import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.labijie.infra.oauth2.client.OpenIdJwtDecoder

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
interface IOpenIDConnectProvider {
    val providerName: String
    val decoder: OpenIdJwtDecoder
    val converter: IOidcUserConverter?
}