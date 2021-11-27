package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.UserPlainObject

class ITwoFactorUserDetailsDeserializer : JsonDeserializer<ITwoFactorUserDetails>() {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): ITwoFactorUserDetails {
        val plain = ctxt.readValue(p, UserPlainObject::class.java)
        return ITwoFactorUserDetails.fromPlainObject(plain)
    }
}