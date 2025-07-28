package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import org.springframework.security.oauth2.core.AuthenticationMethod

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
class AuthenticationMethodSerializer : JsonSerializer<AuthenticationMethod>() {

    override fun serialize(
        value: AuthenticationMethod?,
        gen: JsonGenerator,
        serializers: SerializerProvider?
    ) {
        if(value == null) {
            gen.writeNull()
        }else {
            gen.writeString(value.value)
        }
    }
}