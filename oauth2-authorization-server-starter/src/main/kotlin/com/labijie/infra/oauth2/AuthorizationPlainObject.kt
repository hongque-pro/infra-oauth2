package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.OAuth2ServerUtils.md5Hex
import com.labijie.infra.oauth2.OAuth2ServerUtils.toInstant
import java.time.Duration
import java.time.Instant

class AuthorizationPlainObject {
    var id: String = ""
    var clientId: String = ""
    var principalName: String = ""
    var grantType: String = ""
    var attributes: String = ""
    var state: String? = null
    var authorizationCodeToken: TokenPlainObject? = null
    var accessToken: AccessTokenPlainObject? = null
    var oidcIdToken: TokenPlainObject? = null
    var refreshToken: TokenPlainObject? = null

    companion object {
        fun TokenPlainObject.expiresDurationMills(): Long? {
            if (this.expiresAtEpochSecond != null) {
                return if (this.expiresAtEpochSecond!! > Instant.now().epochSecond) Duration.between(
                    Instant.now(),
                    this.expiresAtEpochSecond.toInstant()
                ).toMillis() else -1L
            }
            return null
        }

        fun TokenPlainObject.tokenId(): String = this.tokenValue.md5Hex()
    }

    fun token(): TokenPlainObject? {
        return accessToken ?: authorizationCodeToken ?: accessToken ?: oidcIdToken
    }

    fun tokenId(): String {
        if(accessToken != null){
            return accessToken!!.tokenId()
        }
        if(authorizationCodeToken != null){
            return accessToken!!.tokenId()
        }
        if(oidcIdToken != null){
            return accessToken!!.tokenId()
        }
        return id
    }

    /**
     * 返回过期事件，如果 token 不存在或没有设置过期事件，表示永不过期，返回 null， 如果已过期返回 -1
     */
    fun expiresDurationMills(): Long? {
        val t = token()
        return t?.expiresDurationMills()
    }


}

open class TokenPlainObject {
    var tokenValue: String = ""
    var issuedAtEpochSecond: Long? = null
    var expiresAtEpochSecond: Long? = null
    var metadata: String = ""
}

class AccessTokenPlainObject : TokenPlainObject() {
    var tokenType: String = ""
    var scopes: Array<String> = arrayOf()
}

