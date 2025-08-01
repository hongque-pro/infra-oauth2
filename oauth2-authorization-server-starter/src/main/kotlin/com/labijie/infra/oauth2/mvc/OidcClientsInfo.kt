package com.labijie.infra.oauth2.mvc

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
data class OidcClientsInfo(
    var enabled: Boolean = false,
    var providers: Set<String>
)