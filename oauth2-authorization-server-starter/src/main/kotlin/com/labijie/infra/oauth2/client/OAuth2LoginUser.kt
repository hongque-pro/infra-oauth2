package com.labijie.infra.oauth2.client

import com.nimbusds.jwt.SignedJWT
import jakarta.servlet.Registration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
class OAuth2LoginUser(
    val provider: String,
    val userId: String,
    val idToken: SignedJWT? = null,
    var email: String? = null,
    var emailVerified: Boolean = false,
    var emailHidden: Boolean? = null,
    var avatar: String? = null,
    var username: String? = null,
    var clientId: String? = null,
) {

    fun setInfo(userInfo: OidcLoginUserInfo) {
        if(userInfo.email.isNotBlank()) {
            this.email = userInfo.email
            this.emailHidden = userInfo.emailVerified
            this.emailVerified = userInfo.emailVerified
        }
        if(!userInfo.avatar.isNullOrBlank()) {
            this.avatar = userInfo.avatar
        }
        if(!userInfo.username.isNullOrBlank()) {
            this.username = userInfo.username
        }
    }
}

data class OidcLoginUserInfo(
    var email: String = "",
    var emailVerified: Boolean = false,
    var emailHidden: Boolean? = null,
    var avatar: String? = null,
    var username: String? = null
)