package com.labijie.infra.oauth2.service

import com.labijie.infra.oauth2.StandardOidcUser
import java.time.Duration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/31
 *
 */
interface IOAuth2ServerOidcTokenService {
    fun encode(user: StandardOidcUser, expiration: Duration, clientId: String? = null): String
    fun decode(idToken: String, ignoreExpiration: Boolean = false): StandardOidcUser
}