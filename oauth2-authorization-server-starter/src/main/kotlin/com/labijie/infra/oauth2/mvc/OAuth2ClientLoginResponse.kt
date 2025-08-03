package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.AccessToken

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/1
 *
 */
class OAuth2ClientLoginResponse private constructor(
    val accessToken: AccessToken? = null,
    val idToken: String? = null,
    error: String? = null,
    description: String? = null): ErrorOptionalResponse(error, description) {

    companion object {
        @JvmStatic
        fun error(error: String, idToken: String, description: String? = null): OAuth2ClientLoginResponse {
            return OAuth2ClientLoginResponse(
                error = error,
                description = description,
                idToken = idToken
            )
        }

        @JvmStatic
        fun success(accessToken: AccessToken): OAuth2ClientLoginResponse {
            return OAuth2ClientLoginResponse(
                accessToken = accessToken
            )
        }
    }
}