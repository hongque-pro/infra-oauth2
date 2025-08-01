package com.labijie.infra.oauth2.mvc

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
data class OAuth2ClientProviderEntry(
    val provider: String,
    val authorizeUri: String,
    val default: Boolean
)