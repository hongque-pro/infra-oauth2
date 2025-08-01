package com.labijie.infra.oauth2.client.exception

import com.labijie.infra.oauth2.OAuth2ClientAuthenticationException
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
open class InvalidOAuth2ClientTokenException: OAuth2ClientAuthenticationException {

    constructor(provider: String, message: String? = null) :
            super(
                provider,
                OAuth2Error(
                    OAuth2ClientErrorCodes.INVALID_OIDC_TOKEN,
                    message.ifNullOrBlank { "Invalid OAuth 2.0 Token from $provider" },
                    null
                )
            )

    constructor(provider: String, clientName: String, message: String?, cause: Throwable) : super(
        provider,
        OAuth2Error(
            OAuth2ClientErrorCodes.INVALID_OIDC_TOKEN,
            message.ifNullOrBlank { "Invalid OAuth 2.0 Token from $clientName" },
            null
        ), cause)

}