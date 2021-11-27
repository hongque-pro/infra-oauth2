package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.type.WritableTypeId
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.jsontype.TypeSerializer
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.toPlainObject

class ITwoFactorUserDetailsSerializer : JsonSerializer<ITwoFactorUserDetails>() {
    override fun serialize(value: ITwoFactorUserDetails, gen: JsonGenerator, serializers: SerializerProvider) {
        val plain = value.toPlainObject()
        serializers.defaultSerializeValue(plain, gen)
    }

    override fun serializeWithType(
        value: ITwoFactorUserDetails,
        gen: JsonGenerator,
        serializers: SerializerProvider,
        typeSer: TypeSerializer
    ) {
        val typeId = typeSer.typeId(value, ITwoFactorUserDetails::class.java, JsonToken.START_OBJECT)
        typeId.include = WritableTypeId.Inclusion.METADATA_PROPERTY

        val typeDefine = typeSer.writeTypePrefix(gen, typeId)
        /*
        var userid:String = "",
        var username:String = "",
        var credentialsNonExpired:Boolean = false,
        var enabled:Boolean = false,
        var password:String = "",
        var accountNonExpired:Boolean = false,
        var accountNonLocked:Boolean = false,
        var twoFactorEnabled: Boolean = false,
        var authorities: ArrayList<String> = arrayListOf(),
        var attachedFields: Map<String, String> = mapOf()
        * */
        val plain = value.toPlainObject()
        serializers.defaultSerializeField(plain::userid.name, plain.userid, gen)
        serializers.defaultSerializeField(plain::username.name, plain.username, gen)
        serializers.defaultSerializeField(plain::credentialsNonExpired.name, plain.credentialsNonExpired, gen)
        serializers.defaultSerializeField(plain::enabled.name, plain.enabled, gen)
        serializers.defaultSerializeField(plain::password.name, plain.password, gen)
        serializers.defaultSerializeField(plain::accountNonExpired.name, plain.accountNonExpired, gen)
        serializers.defaultSerializeField(plain::accountNonLocked.name, plain.accountNonLocked, gen)
        serializers.defaultSerializeField(plain::twoFactorEnabled.name, plain.twoFactorEnabled, gen)
        serializers.defaultSerializeField(plain::authorities.name, plain.authorities, gen)
        serializers.defaultSerializeField(plain::attachedFields.name, plain.attachedFields, gen)
        typeSer.writeTypeSuffix(gen, typeDefine)
    }
}