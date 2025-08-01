package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.client.OAuth2ClientErrorCodes
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/26
 *
 */
class OidcLoginResult {

    private val signInUser: ITwoFactorUserDetails?

    private val error: OAuth2Error?

    companion object {
        val OidcLoginResult.isSuccess: Boolean get() = signInUser != null

        val OidcLoginResult.isFailure: Boolean get() = signInUser == null

        fun OidcLoginResult.getUser(): ITwoFactorUserDetails {
            return getOrElse { throw it }
        }

        fun OidcLoginResult.getOrElse(onFailure: (exception: OAuth2AuthenticationException) -> ITwoFactorUserDetails): ITwoFactorUserDetails {
            if (signInUser != null) return signInUser
            return onFailure(OAuth2AuthenticationException(error!!))
        }

        fun success(signedInUser: ITwoFactorUserDetails): OidcLoginResult = OidcLoginResult(signedInUser)

        fun failure(errorCode: String, errorDescription: String? = null, uri: String? = null): OidcLoginResult =
            OidcLoginResult(errorCode, errorDescription, uri)

        fun accountNotRegistered(): OidcLoginResult = OidcLoginResult(
            OAuth2ClientErrorCodes.OAUTH2_ACCOUNT_NOT_REGISTERED,
            "OAuth2 user must be registered as an application account."
        )

    }

    fun errorOrNull(): OAuth2Error? = error

    private constructor(signedInUser: ITwoFactorUserDetails) {
        this.signInUser = signedInUser
        this.error = null
    }

    private constructor(errorCode: String, errorDescription: String? = null, uri: String? = null) {
        if (errorCode.isBlank()) {
            throw IllegalArgumentException("Error code cannot be null or blank when construct OidcLoginResponse")
        }
        this.signInUser = null
        this.error = OAuth2Error(errorCode, errorDescription, uri)
    }
}


