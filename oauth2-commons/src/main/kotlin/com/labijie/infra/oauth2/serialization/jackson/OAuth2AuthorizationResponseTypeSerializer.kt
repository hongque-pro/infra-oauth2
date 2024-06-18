/**
 * @author Anders Xiao
 * @date 2024-06-18
 */
package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType


class OAuth2AuthorizationResponseTypeSerializer: JsonSerializer<OAuth2AuthorizationResponseType>() {
    override fun serialize(value: OAuth2AuthorizationResponseType?, gen: JsonGenerator, provider: SerializerProvider?) {
        if(value == null) {
            gen.writeNull()
        }else {
            gen.writeString(value.value)
        }
    }
}