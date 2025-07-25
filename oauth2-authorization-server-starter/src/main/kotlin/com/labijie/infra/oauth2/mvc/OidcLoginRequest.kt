package com.labijie.infra.oauth2.mvc

import jakarta.validation.constraints.NotBlank

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
class OidcLoginRequest {
    @NotBlank
    var idToken: String = ""

    var authorizationCode: String? = null

    var nonce: String? = null

    var attributes: MutableMap<String, String>? = null

    var userDisplayName: String? = null
}