package com.labijie.infra.oauth2.resource.oauth2.apple

import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/21
 *
 */
class AppleAuthenticationException(message: String? = null) : OAuth2AuthenticationException(OAuth2Error("invalid_apple_token", message, null)) {
}