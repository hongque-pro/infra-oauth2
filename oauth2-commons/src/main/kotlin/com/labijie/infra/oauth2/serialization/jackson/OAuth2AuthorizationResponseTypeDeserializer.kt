/**
 * @author Anders Xiao
 * @date 2024-06-18
 */
package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonSerializer
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import java.math.BigDecimal


class OAuth2AuthorizationResponseTypeDeserializer : JsonDeserializer<OAuth2AuthorizationResponseType>() {
    override fun deserialize(p: JsonParser, p1: DeserializationContext): OAuth2AuthorizationResponseType? {
        val rawValue = p.text?.trim('"')
        if(rawValue != null){
            return OAuth2AuthorizationResponseType(rawValue)
        }
        return null
    }
}