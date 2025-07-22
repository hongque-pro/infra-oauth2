package com.labijie.infra.oauth2.client.exception

import com.labijie.infra.oauth2.client.OAuth2ClientErrorCodes
import com.labijie.infra.utils.ifNullOrBlank
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
class InvalidOauth2ClientTokenResponseException : OAuth2AuthenticationException {

    constructor(clientName: String, message: String? = null) : super(
        OAuth2Error(
            OAuth2ClientErrorCodes.INVALID_TOKEN_RESPONSE_ERROR_CODE,
            message.ifNullOrBlank { "Invalid OAuth 2.0 Token Response" },
            null
        )
    ) {
        this.clientName = clientName
    }

    constructor(clientName: String, message: String?, cause: Throwable) : super(
        OAuth2Error(
            OAuth2ClientErrorCodes.INVALID_TOKEN_RESPONSE_ERROR_CODE,
            message.ifNullOrBlank { "Invalid OAuth 2.0 Token Response" },
            null
        ), cause
    ) {
        this.clientName = clientName
    }

    val clientName: String
}