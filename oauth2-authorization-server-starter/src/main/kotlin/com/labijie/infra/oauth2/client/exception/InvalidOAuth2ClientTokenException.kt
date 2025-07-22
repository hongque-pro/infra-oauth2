package com.labijie.infra.oauth2.client.exception

import com.labijie.infra.oauth2.client.OAuth2ClientErrorCodes
import com.labijie.infra.utils.ifNullOrBlank
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/21
 *
 */
open class InvalidOAuth2ClientTokenException: OAuth2AuthenticationException {

    private val clientName: String

    constructor(clientName: String, message: String? = null) :
            super(
                OAuth2Error(
                    OAuth2ClientErrorCodes.INVALID_OAUTH2_CLIENT_TOKEN,
                    message.ifNullOrBlank { "Invalid OAuth 2.0 Token from $clientName" },
                    null
                )
            ){
                this.clientName = clientName
            }

    constructor(clientName: String, message: String?, cause: Throwable) : super(
        OAuth2Error(
            OAuth2ClientErrorCodes.INVALID_OAUTH2_CLIENT_TOKEN,
            message.ifNullOrBlank { "Invalid OAuth 2.0 Token from $clientName" },
            null
        ), cause) {
        this.clientName = clientName
    }

}