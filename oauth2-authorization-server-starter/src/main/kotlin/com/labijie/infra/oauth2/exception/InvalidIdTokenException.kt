package com.labijie.infra.oauth2.exception

import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/1
 *
 */
class InvalidIdTokenException(message: String? = null, cause: Throwable? = null) :
    OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "Invalid ID token", null), message) {
}