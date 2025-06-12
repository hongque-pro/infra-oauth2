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
    var attributes: ByteArray? = null
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

        fun tokenValueToId(tokenValue: String) = tokenValue.md5Hex()

        fun TokenPlainObject.tokenId(): String = tokenValueToId(this.tokenValue)
    }

    fun token(): TokenPlainObject? {
        return accessToken ?: authorizationCodeToken ?: oidcIdToken
    }

    fun tokenId(): String {
        if(accessToken != null){
            return accessToken!!.tokenId()
        }
        if(authorizationCodeToken != null){
            return authorizationCodeToken!!.tokenId()
        }
        if(oidcIdToken != null){
            return oidcIdToken!!.tokenId()
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
    var metadata: ByteArray? = null
}

class AccessTokenPlainObject : TokenPlainObject() {
    var tokenType: String = ""
    var scopes: Array<String> = arrayOf()
}

