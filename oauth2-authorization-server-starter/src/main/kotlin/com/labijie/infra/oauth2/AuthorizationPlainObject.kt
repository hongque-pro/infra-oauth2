package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.OAuth2ServerUtils.md5Hex
import com.labijie.infra.oauth2.OAuth2ServerUtils.toInstant
import com.labijie.infra.utils.toByteArray
import com.labijie.infra.utils.toInt
import com.labijie.infra.utils.toLong
import java.net.URI
import java.net.URL
import java.time.Duration
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*

class AuthorizationPlainObject {
    var id: String = ""
    var clientId: String = ""
    var principalName: String = ""
    var grantType: String = ""

    //var attributes: ByteArray? = null
    var state: String? = null
    var scopes: Set<String> = emptySet()
    var authorizationCodeToken: TokenPlainObject? = null
    var accessToken: AccessTokenPlainObject? = null
    var oidcIdToken: TokenPlainObject? = null
    var refreshToken: TokenPlainObject? = null
    var user: UserPlainObject? = null


    companion object {
        fun ITokenPlainObject.expiresDurationMills(): Long? {
            if (this.expiresAtEpochSecond != null) {
                return if (this.expiresAtEpochSecond!! > Instant.now().epochSecond) Duration.between(
                    Instant.now(),
                    this.expiresAtEpochSecond.toInstant()
                ).toMillis() else -1L
            }
            return null
        }

        fun tokenValueToId(tokenValue: String) = tokenValue.md5Hex()

        fun ITokenPlainObject.tokenId(): String = tokenValueToId(this.tokenValue)
    }

    fun token(): ITokenPlainObject? {
        return accessToken ?: authorizationCodeToken ?: oidcIdToken
    }

    fun tokenId(): String {
        if (accessToken != null) {
            return accessToken!!.tokenId()
        }
        if (authorizationCodeToken != null) {
            return authorizationCodeToken!!.tokenId()
        }
        if (oidcIdToken != null) {
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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthorizationPlainObject

        if (id != other.id) return false
        if (clientId != other.clientId) return false
        if (principalName != other.principalName) return false
        if (grantType != other.grantType) return false
        if (state != other.state) return false
        if (scopes != other.scopes) return false
        if (authorizationCodeToken != other.authorizationCodeToken) return false
        if (accessToken != other.accessToken) return false
        if (oidcIdToken != other.oidcIdToken) return false
        if (refreshToken != other.refreshToken) return false
        if (user != other.user) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + clientId.hashCode()
        result = 31 * result + principalName.hashCode()
        result = 31 * result + grantType.hashCode()
        result = 31 * result + (state?.hashCode() ?: 0)
        result = 31 * result + scopes.hashCode()
        result = 31 * result + (authorizationCodeToken?.hashCode() ?: 0)
        result = 31 * result + (accessToken?.hashCode() ?: 0)
        result = 31 * result + (oidcIdToken?.hashCode() ?: 0)
        result = 31 * result + (refreshToken?.hashCode() ?: 0)
        result = 31 * result + (user?.hashCode() ?: 0)
        return result
    }


}

enum class MetadataType {
    Unknown,
    ByteArray,
    String,
    Int,
    Long,
    Instant,
    LocalDateTime,
    Duration,
    Locale,
    URL,
    URI,
    UUID,
    Boolean
}

class MetadataTypedValue(var type: MetadataType = MetadataType.Unknown, var value: ByteArray? = null) {

    companion object {

        internal fun Any.toMetadataValue(): MetadataTypedValue = when (this) {
            is Int -> MetadataTypedValue(MetadataType.Int, this.toByteArray())
            is String -> MetadataTypedValue(MetadataType.String, this.toByteArray(Charsets.UTF_8))
            is Long -> MetadataTypedValue(MetadataType.Long, this.toByteArray())
            is Instant -> MetadataTypedValue(MetadataType.Instant, this.toEpochMilli().toByteArray())
            is LocalDateTime -> MetadataTypedValue(
                MetadataType.LocalDateTime, this.toInstant(
                    ZoneOffset.UTC
                ).toEpochMilli().toByteArray()
            )

            is Duration -> MetadataTypedValue(MetadataType.Duration, this.toMillis().toByteArray())
            is ByteArray -> MetadataTypedValue(MetadataType.ByteArray, this)
            is Locale -> MetadataTypedValue(MetadataType.Locale, this.toLanguageTag().toByteArray(Charsets.UTF_8))
            is URL -> MetadataTypedValue(MetadataType.URL, this.toString().toByteArray(Charsets.UTF_8))
            is URI -> MetadataTypedValue(MetadataType.URI, this.toString().toByteArray(Charsets.UTF_8))
            is UUID -> MetadataTypedValue(MetadataType.UUID, this.toString().toByteArray(Charsets.UTF_8))
            is Boolean -> MetadataTypedValue(MetadataType.Boolean, if (this) byteArrayOf(1) else byteArrayOf(0))
            else -> throw RuntimeException("Unsupported oauth2 token metadata type: ${this::class.java}")
        }


        internal fun MetadataTypedValue.getValue(): Any? {
            return when (this.type) {
                MetadataType.ByteArray -> this.value
                MetadataType.String -> this.value?.toString(Charsets.UTF_8)
                MetadataType.Int -> this.value?.toInt()
                MetadataType.Long -> this.value?.toLong()
                MetadataType.Instant -> this.value?.toLong()?.let { Instant.ofEpochMilli(it) }
                MetadataType.LocalDateTime -> this.value?.toLong()
                    ?.let { mills -> Instant.ofEpochMilli(mills).let { LocalDateTime.ofInstant(it, ZoneOffset.UTC) } }

                MetadataType.Duration -> this.value?.toLong()?.let { Duration.ofMillis(it) }
                MetadataType.Locale -> this.value?.toString(Charsets.UTF_8)?.let { Locale.of(it) }
                MetadataType.URL -> this.value?.toString(Charsets.UTF_8)?.let { URL.of(URI.create(it), null) }
                MetadataType.URI -> this.value?.toString(Charsets.UTF_8)?.let { URI.create(it) }
                MetadataType.UUID -> this.value?.toString(Charsets.UTF_8)?.let { UUID.fromString(it) }
                MetadataType.Boolean -> this.value?.firstOrNull()?.let { if (it == 1.toByte()) true else false }
                MetadataType.Unknown -> throw RuntimeException("OAuth2 token metadata type unknown")
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MetadataTypedValue

        if (type != other.type) return false
        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (value?.contentHashCode() ?: 0)
        return result
    }
}


interface ITokenPlainObject {
    var tokenValue: String
    var issuedAtEpochSecond: Long?
    var expiresAtEpochSecond: Long?
    var claims: Map<String, MetadataTypedValue>?
    var invalidated: Boolean?
}

class TokenPlainObject(
    override var tokenValue: String = "",
    override var issuedAtEpochSecond: Long? = null,
    override var expiresAtEpochSecond: Long? = null,
    override var claims: Map<String, MetadataTypedValue>? = null,
    override var invalidated: Boolean? = null,
) : ITokenPlainObject {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TokenPlainObject

        if (issuedAtEpochSecond != other.issuedAtEpochSecond) return false
        if (expiresAtEpochSecond != other.expiresAtEpochSecond) return false
        if (invalidated != other.invalidated) return false
        if (tokenValue != other.tokenValue) return false
        if (claims != other.claims) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuedAtEpochSecond?.hashCode() ?: 0
        result = 31 * result + (expiresAtEpochSecond?.hashCode() ?: 0)
        result = 31 * result + (invalidated?.hashCode() ?: 0)
        result = 31 * result + tokenValue.hashCode()
        result = 31 * result + (claims?.hashCode() ?: 0)
        return result
    }

}

class AccessTokenPlainObject(
    override var tokenValue: String = "",
    override var issuedAtEpochSecond: Long? = null,
    override var expiresAtEpochSecond: Long? = null,
    override var claims: Map<String, MetadataTypedValue>? = null,
    override var invalidated: Boolean? = null,

    var tokenType: String = "",
    var scopes: Array<String> = arrayOf(),
) : ITokenPlainObject {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AccessTokenPlainObject

        if (issuedAtEpochSecond != other.issuedAtEpochSecond) return false
        if (expiresAtEpochSecond != other.expiresAtEpochSecond) return false
        if (invalidated != other.invalidated) return false
        if (tokenValue != other.tokenValue) return false
        if (claims != other.claims) return false
        if (tokenType != other.tokenType) return false
        if (!scopes.contentEquals(other.scopes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuedAtEpochSecond?.hashCode() ?: 0
        result = 31 * result + (expiresAtEpochSecond?.hashCode() ?: 0)
        result = 31 * result + (invalidated?.hashCode() ?: 0)
        result = 31 * result + tokenValue.hashCode()
        result = 31 * result + (claims?.hashCode() ?: 0)
        result = 31 * result + tokenType.hashCode()
        result = 31 * result + scopes.contentHashCode()
        return result
    }

}

