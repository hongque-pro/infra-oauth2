package com.labijie.infra.oauth2.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.SimpleTwoFactorUserDetails

open class OAuth2JacksonModule : SimpleModule("infra-oauth2") {
    init {
        this.addSerializer(ITwoFactorUserDetails::class.java, ITwoFactorUserDetailsSerializer())
        this.addDeserializer(ITwoFactorUserDetails::class.java, ITwoFactorUserDetailsDeserializer())
    }
}