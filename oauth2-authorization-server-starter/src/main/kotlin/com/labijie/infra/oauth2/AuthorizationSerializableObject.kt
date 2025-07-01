package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.AccessTokenSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.AccessTokenSerializableObject.Companion.asSerializable
import com.labijie.infra.oauth2.TokenSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.TokenSerializableObject.Companion.asSerializable
import com.labijie.infra.oauth2.UserSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.UserSerializableObject.Companion.asSerializable
import kotlinx.serialization.Serializable


@Serializable
internal data class UserSerializableObject(
    var userid:String = "",
    var username:String = "",
    var credentialsNonExpired:Boolean = false,
    var enabled:Boolean = false,
    var password:String = "",
    var accountNonExpired:Boolean = false,
    var accountNonLocked:Boolean = false,
    var twoFactorEnabled: Boolean = false,
    var authorities: List<String> = emptyList(),
    var attachedFields: Map<String, String> = emptyMap()
) {
    companion object {
        fun UserPlainObject.asSerializable() = UserSerializableObject(
            userid = this.userid,
            username = this.username,
            credentialsNonExpired = this.credentialsNonExpired,
            enabled = this.enabled,
            accountNonExpired = this.accountNonExpired,
            accountNonLocked = this.accountNonLocked,
            twoFactorEnabled = this.twoFactorEnabled,
            authorities = this.authorities.toList(),
            attachedFields = this.attachedFields,
        )
        fun UserSerializableObject.asPlain() = UserPlainObject(
            userid = this.userid,
            username = this.username,
            credentialsNonExpired = this.credentialsNonExpired,
            enabled = this.enabled,
            accountNonExpired = this.accountNonExpired,
            accountNonLocked = this.accountNonLocked,
            twoFactorEnabled = this.twoFactorEnabled,
            authorities = this.authorities.toTypedArray(),
            attachedFields = this.attachedFields
        )
    }
}

@Serializable
internal class AuthorizationSerializableObject {
    var id: String = ""
    var clientId: String = ""
    var principalName: String = ""
    var grantType: String = ""
    var state: String? = null
    var authorizationCodeToken: TokenSerializableObject? = null
    var accessToken: AccessTokenSerializableObject? = null
    var oidcIdToken: TokenSerializableObject? = null
    var refreshToken: TokenSerializableObject? = null
    var user: UserSerializableObject? = null
    var scopes: Set<String> = emptySet()


    companion object {
        fun AuthorizationPlainObject.asSerializable() = AuthorizationSerializableObject().also {
            it.id = id
            it.clientId = clientId
            it.principalName = principalName
            it.principalName = principalName
            it.grantType = grantType
            //it.attributes = attributes
            it.state = state
            it.authorizationCodeToken = authorizationCodeToken?.asSerializable()
            it.accessToken =  accessToken?.asSerializable()
            it.oidcIdToken = oidcIdToken?.asSerializable()
            it.refreshToken = refreshToken?.asSerializable()
            it.user = user?.asSerializable()
            it.scopes = scopes
        }

        fun AuthorizationSerializableObject.asPlain() = AuthorizationPlainObject().also {
            it.id = id
            it.clientId = clientId
            it.principalName = principalName
            it.principalName = principalName
            it.grantType = grantType
            //it.attributes = attributes
            it.state = state
            it.authorizationCodeToken = authorizationCodeToken?.asPlain()
            it.accessToken =  accessToken?.asPlain()
            it.oidcIdToken = oidcIdToken?.asPlain()
            it.refreshToken = refreshToken?.asPlain()
            it.user = user?.asPlain()
            it.scopes = scopes
        }
    }


}

@Serializable
internal class MetadataSerializableValue(var type: MetadataType = MetadataType.Unknown, var value: ByteArray? = null)

@Serializable
internal class TokenSerializableObject(
    var tokenValue: String = "",
    var issuedAtEpochSecond: Long? = null,
    var expiresAtEpochSecond: Long? = null,
    var invalidated: Boolean? = null,
    var claims: Map<String, MetadataSerializableValue>? = null
) {

    companion object {
        fun TokenPlainObject.asSerializable() = TokenSerializableObject().also {
            it.tokenValue = tokenValue
            it.issuedAtEpochSecond = issuedAtEpochSecond
            it.expiresAtEpochSecond = expiresAtEpochSecond
            it.invalidated = invalidated
            it.claims = claims?.map { kv -> kv.key to MetadataSerializableValue(kv.value.type, kv.value.value) }?.toMap()
        }

        fun TokenSerializableObject.asPlain() = TokenPlainObject().also {
            it.tokenValue = tokenValue
            it.issuedAtEpochSecond = issuedAtEpochSecond
            it.expiresAtEpochSecond = expiresAtEpochSecond
            it.invalidated = invalidated
            it.claims = claims?.map { kv -> kv.key to MetadataTypedValue(kv.value.type, kv.value.value) }?.toMap()
        }
    }
}

@Serializable
internal class AccessTokenSerializableObject(
    var tokenValue: String = "",
    var issuedAtEpochSecond: Long? = null,
    var expiresAtEpochSecond: Long? = null,
    var invalidated: Boolean? = null,
    var claims: Map<String, MetadataSerializableValue>? = null,

    var tokenType: String = "",
    var scopes: Array<String> = arrayOf(),
) {

    companion object {
        fun AccessTokenPlainObject.asSerializable() = AccessTokenSerializableObject().also {
            it.tokenValue = tokenValue
            it.issuedAtEpochSecond = issuedAtEpochSecond
            it.expiresAtEpochSecond = expiresAtEpochSecond
            it.tokenType = tokenType
            it.scopes = scopes
            it.invalidated = invalidated
            it.claims = claims?.map { kv -> kv.key to MetadataSerializableValue(kv.value.type, kv.value.value) }?.toMap()
        }

        fun AccessTokenSerializableObject.asPlain() = AccessTokenPlainObject().also {
            it.tokenValue = tokenValue
            it.issuedAtEpochSecond = issuedAtEpochSecond
            it.expiresAtEpochSecond = expiresAtEpochSecond
            it.tokenType = tokenType
            it.scopes = scopes
            it.invalidated = invalidated
            it.claims = claims?.map { kv -> kv.key to MetadataTypedValue(kv.value.type, kv.value.value) }?.toMap()
        }
    }
}

