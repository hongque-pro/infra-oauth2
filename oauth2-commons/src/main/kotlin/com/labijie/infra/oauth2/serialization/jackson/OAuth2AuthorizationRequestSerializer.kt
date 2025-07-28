package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.labijie.infra.oauth2.serialization.PlainOAuth2AuthorizationRequest.Companion.toPlain
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
class OAuth2AuthorizationRequestSerializer : JsonSerializer<OAuth2AuthorizationRequest>() {
    override fun serialize(
        value: OAuth2AuthorizationRequest?,
        gen: JsonGenerator,
        serializers: SerializerProvider
    ) {
        gen.writeObject(value?.toPlain())
    }
}