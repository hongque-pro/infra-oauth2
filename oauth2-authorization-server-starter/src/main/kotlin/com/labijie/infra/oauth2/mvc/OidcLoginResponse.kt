package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/26
 *
 */
class OidcLoginResponse {

    private val accessToken: AccessToken?

    private val error: OAuth2Error?

    companion object {
        val OidcLoginResponse.isSuccess: Boolean get() = accessToken != null

        val OidcLoginResponse.isFailure: Boolean get() = accessToken == null

        fun OidcLoginResponse.getOrElse(onFailure: (exception: OAuth2AuthenticationException) -> AccessToken): AccessToken {

            if(accessToken != null) return accessToken

            return onFailure(OAuth2AuthenticationException(error!!))
        }
    }

    fun errorOrNull(): OAuth2Error? = error

    constructor(accessToken: AccessToken) {
        this.accessToken = accessToken
        this.error = null
    }

    constructor(errorCode: String, errorDescription: String? = null, uri: String? = null) {
        if(errorCode.isBlank()) {
            throw IllegalArgumentException("Error code cannot be null or blank when construct OidcLoginResponse")
        }
        this.accessToken = null
        this.error = OAuth2Error(errorCode, errorDescription, uri)
    }
}


