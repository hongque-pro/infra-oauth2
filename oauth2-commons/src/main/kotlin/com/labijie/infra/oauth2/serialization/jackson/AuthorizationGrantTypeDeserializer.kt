/**
 * @author Anders Xiao
 * @date 2024-06-18
 */
package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import org.springframework.security.oauth2.core.AuthorizationGrantType


class AuthorizationGrantTypeDeserializer : JsonDeserializer<AuthorizationGrantType>() {
    override fun deserialize(p: JsonParser, p1: DeserializationContext): AuthorizationGrantType? {
        val rawValue = p.text?.trim('"')
        if(rawValue != null){
            return AuthorizationGrantType(rawValue)
        }
        return null
    }
}