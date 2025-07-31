package com.labijie.infra.oauth2.client.exception

import com.labijie.infra.oauth2.OAuth2ClientAuthenticationException
import com.labijie.infra.oauth2.client.OAuth2ClientErrorCodes
import com.labijie.infra.utils.ifNullOrBlank
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/31
 *
 */
class OAuth2AccountLinkedAnotherUserException  : OAuth2ClientAuthenticationException {

    constructor(provider: String, message: String? = null) : super(
        provider,
        OAuth2Error(
            OAuth2ClientErrorCodes.OAUTH2_ACCOUNT_LINKED_ANOTHER_USER,
            message.ifNullOrBlank { "The OAuth2 account you are trying to link is already associated with a different user." },
            null
        )
    )

    constructor(provider: String, message: String?, cause: Throwable) : super(
        provider,
        OAuth2Error(
            OAuth2ClientErrorCodes.OAUTH2_ACCOUNT_LINKED_ANOTHER_USER,
            message.ifNullOrBlank { "The OAuth2 account you are trying to link is already associated with a different user." },
            null
        ), cause
    )
}