package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.ITwoFactorUserDetails

open class OAuth2JacksonModule : SimpleModule("infra.oauth2.server") {
    init {
        this.addSerializer(ITwoFactorUserDetails::class.java, ITwoFactorUserDetailsSerializer())
        this.addDeserializer(ITwoFactorUserDetails::class.java, ITwoFactorUserDetailsDeserializer())
    }
}