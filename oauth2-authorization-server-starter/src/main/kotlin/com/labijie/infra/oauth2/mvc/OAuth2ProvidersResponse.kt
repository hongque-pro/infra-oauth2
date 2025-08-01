package com.labijie.infra.oauth2.mvc

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/1
 *
 */
data class OAuth2ProvidersResponse(
    val oauth2: OAuth2ClientsInfo,
    val oidc: OidcClientsInfo
)