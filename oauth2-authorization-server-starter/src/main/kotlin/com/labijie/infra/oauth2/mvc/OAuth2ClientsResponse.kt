package com.labijie.infra.oauth2.mvc

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
data class OAuth2ClientsResponse(
    var enabled: Boolean,
    var providers: List<OAuth2ClientProviderEntry> = emptyList(),
)