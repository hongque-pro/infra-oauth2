package com.labijie.infra.oauth2.client.exception

import com.labijie.infra.oauth2.OAuth2ClientAuthenticationException
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
class InvalidOAuth2ClientProviderException : OAuth2ClientAuthenticationException {

    constructor(provider: String, message: String? = null) :
            super(
                provider,
                OAuth2Error(
                    OAuth2ClientErrorCodes.INVALID_OAUTH2_CLIENT_PROVIDER,
                    message.ifNullOrBlank { "OAuth client provider with name '$provider' unsupported." },
                    null
                )
            )
}