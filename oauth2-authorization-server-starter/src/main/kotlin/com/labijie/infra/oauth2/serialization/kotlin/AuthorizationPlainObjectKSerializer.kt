package com.labijie.infra.oauth2.serialization.kotlin

import com.labijie.infra.oauth2.AuthorizationPlainObject
import com.labijie.infra.oauth2.AuthorizationSerializableObject
import com.labijie.infra.oauth2.AuthorizationSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.AuthorizationSerializableObject.Companion.asSerializable
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/30
 *
 */
object AuthorizationPlainObjectKSerializer : KSerializer<AuthorizationPlainObject> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("com.labijie.infra.oauth2.AuthorizationPlainObject")

    override fun deserialize(decoder: Decoder): AuthorizationPlainObject {
        val obj = decoder.decodeSerializableValue(AuthorizationSerializableObject.serializer())
        return obj.asPlain()
    }

    override fun serialize(
        encoder: Encoder,
        value: AuthorizationPlainObject
    ) {
        val obj = value.asSerializable()
        encoder.encodeSerializableValue(AuthorizationSerializableObject.serializer(), obj)
    }
}