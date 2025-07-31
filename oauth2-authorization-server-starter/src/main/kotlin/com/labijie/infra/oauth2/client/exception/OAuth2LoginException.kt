package com.labijie.infra.oauth2.client.exception

import com.labijie.infra.oauth2.OAuth2ClientAuthenticationException
import com.labijie.infra.oauth2.StandardOidcUserInfo
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/26
 *
 */
class OAuth2LoginException : OAuth2ClientAuthenticationException {

    var userInfo: StandardOidcUserInfo?
        get() {
            return details["userInfo"] as? StandardOidcUserInfo
        }
        set(value) {
            if (value == null) {
                details.remove("userInfo")
            } else {
                details["userInfo"] = value
            }
        }

    constructor(
        provider: String,
        error: OAuth2Error, cause: Throwable? = null
    ) : super(provider, error, cause)


    constructor(
        provider: String,
        errorCode: String, errorDescription: String? = null, uri: String? = null, cause: Throwable? = null
    ) : super(provider, OAuth2Error(errorDescription, errorDescription, uri), cause)
}