package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.labijie.infra.oauth2.serialization.PlainOAuth2AuthorizationRequest
import com.labijie.infra.oauth2.serialization.PlainOAuth2AuthorizationRequest.Companion.toOAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
class OAuth2AuthorizationRequestDeserializer : JsonDeserializer<OAuth2AuthorizationRequest>() {
    override fun deserialize(
        p: JsonParser,
        ctxt: DeserializationContext
    ): OAuth2AuthorizationRequest? {
        val plain = ctxt.readValue(p, PlainOAuth2AuthorizationRequest::class.java)
        return plain.toOAuth2AuthorizationRequest()
    }
}