package com.labijie.infra.oauth2.client

import com.nimbusds.jwt.SignedJWT
import net.minidev.json.annotate.JsonIgnore

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
class StandardOidcUser(
    val provider: String,
    val userId: String,
    @JsonIgnore
    val idToken: SignedJWT? = null,
    var email: String? = null,
    var emailVerified: Boolean = false,
    var emailHidden: Boolean? = null,
    var picture: String? = null,
    var username: String? = null,
    var clientId: String? = null,
) {

    fun setInfo(userInfo: StandardOidcUserInfo) {
        if(userInfo.email.isNotBlank()) {
            this.email = userInfo.email
            this.emailHidden = userInfo.emailVerified
            this.emailVerified = userInfo.emailVerified
        }
        if(!userInfo.picture.isNullOrBlank()) {
            this.picture = userInfo.picture
        }
        if(!userInfo.username.isNullOrBlank()) {
            this.username = userInfo.username
        }
    }

    fun getInfo(): StandardOidcUserInfo {
        return StandardOidcUserInfo().also {
            it.username = this.username
            it.email = this.email.orEmpty()
            it.emailVerified = this.emailVerified
            it.emailHidden = this.emailHidden
            it.picture = this.picture
        }
    }
}

data class StandardOidcUserInfo(
    var email: String = "",
    var emailVerified: Boolean = false,
    var emailHidden: Boolean? = null,
    var picture: String? = null,
    var username: String? = null,
    var nickname: String? = null,
)