package com.labijie.infra.oauth2

import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
open class OAuth2ClientAuthenticationException : OAuth2AuthenticationException {
    val provider: String
    val details: MutableMap<String, Any> = mutableMapOf()

    constructor(provider: String, errorCode: String?) : super(errorCode) {
        this.provider = provider
        if(provider.isNotBlank()) {
            details["provider"] = provider
        }
    }
    constructor(provider: String, error: OAuth2Error?) : super(error) {
        this.provider = provider
        if(provider.isNotBlank()) {
            details["provider"] = provider
        }
    }
    constructor(provider: String, error: OAuth2Error?, cause: Throwable?) : super(error, cause) {
        this.provider = provider
        if(provider.isNotBlank()) {
            details["provider"] = provider
        }
    }
    constructor(provider: String, error: OAuth2Error?, message: String?) : super(error, message) {
        this.provider = provider
        if(provider.isNotBlank()) {
            details["provider"] = provider
        }
    }
    constructor(provider: String, error: OAuth2Error?, message: String?, cause: Throwable?) : super(error, message, cause) {
        this.provider = provider
        if(provider.isNotBlank()) {
            details["provider"] = provider
        }
    }
}