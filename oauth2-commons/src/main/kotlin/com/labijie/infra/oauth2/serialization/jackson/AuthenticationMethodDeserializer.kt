package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import org.springframework.security.oauth2.core.AuthenticationMethod

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
class AuthenticationMethodDeserializer : JsonDeserializer<AuthenticationMethod>() {
    override fun deserialize(p: JsonParser, p1: DeserializationContext): AuthenticationMethod? {
        val rawValue = p.text?.trim('"')
        if(rawValue != null){
            return AuthenticationMethod(rawValue)
        }
        return null
    }
}