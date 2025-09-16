package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.AccessTokenSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.AccessTokenSerializableObject.Companion.asSerializable
import com.labijie.infra.oauth2.OAuth2ServerUtils.toArrayList
import com.labijie.infra.oauth2.OAuth2ServerUtils.toHashMap
import com.labijie.infra.oauth2.TokenSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.TokenSerializableObject.Companion.asSerializable
import com.labijie.infra.oauth2.UserSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.UserSerializableObject.Companion.asSerializable
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.protobuf.ProtoNumber

@ExperimentalSerializationApi
@Serializable
internal data class UserSerializableObject constructor(
    @ProtoNumber(1) var userid:String = "",
    @ProtoNumber(2) var username:String = "",
    @ProtoNumber(3) var credentialsNonExpired:Boolean = false,
    @ProtoNumber(4) var enabled:Boolean = false,
    @ProtoNumber(5) var password:String = "",
    @ProtoNumber(6) var accountNonExpired:Boolean = false,
    @ProtoNumber(7) var accountNonLocked:Boolean = false,
    @ProtoNumber(8) var twoFactorEnabled: Boolean = false,
    @ProtoNumber(9) var authorities: List<String> = emptyList(),
    @ProtoNumber(10) var attachedFields: Map<String, String> = emptyMap()
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
            authorities = this.authorities,
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
            authorities = this.authorities.toArrayList(),
            attachedFields = this.attachedFields.toHashMap()
        )
    }
}

@Serializable
@ExperimentalSerializationApi
internal class AuthorizationSerializableObject {
    @ProtoNumber(1) var id: String = ""
    @ProtoNumber(2) var clientId: String = ""
    @ProtoNumber(3) var principalName: String = ""
    @ProtoNumber(4) var grantType: String = ""
    @ProtoNumber(5) var state: String? = null
    @ProtoNumber(6) var authorizationCodeToken: TokenSerializableObject? = null
    @ProtoNumber(7) var accessToken: AccessTokenSerializableObject? = null
    @ProtoNumber(8) var oidcIdToken: TokenSerializableObject? = null
    @ProtoNumber(9) var refreshToken: TokenSerializableObject? = null
    @ProtoNumber(10)  var user: UserSerializableObject? = null
    @ProtoNumber(11)  var scopes: HashSet<String> = HashSet(0)


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
@ExperimentalSerializationApi
internal class MetadataSerializableValue(
    @ProtoNumber(1) var type: MetadataType = MetadataType.Unknown,
    @ProtoNumber(2) var value: ByteArray? = null)

@Serializable
@ExperimentalSerializationApi
internal class TokenSerializableObject(
    @ProtoNumber(1) var tokenValue: String = "",
    @ProtoNumber(2) var issuedAtEpochSecond: Long? = null,
    @ProtoNumber(3) var expiresAtEpochSecond: Long? = null,
    @ProtoNumber(4) var invalidated: Boolean? = null,
    @ProtoNumber(5)  var claims: Map<String, MetadataSerializableValue>? = null
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
@ExperimentalSerializationApi
internal class AccessTokenSerializableObject(
    @ProtoNumber(1) var tokenValue: String = "",
    @ProtoNumber(2) var issuedAtEpochSecond: Long? = null,
    @ProtoNumber(3) var expiresAtEpochSecond: Long? = null,
    @ProtoNumber(4) var invalidated: Boolean? = null,
    @ProtoNumber(5) var claims: Map<String, MetadataSerializableValue>? = null,

    @ProtoNumber(6) var tokenType: String = "",
    @ProtoNumber(7) var scopes: Array<String> = arrayOf(),
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

