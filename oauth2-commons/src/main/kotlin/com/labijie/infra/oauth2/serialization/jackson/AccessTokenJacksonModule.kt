/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.labijie.infra.oauth2.AccessToken


class AccessTokenJacksonModule : SimpleModule("infra.oauth2.access-token") {
    init {
        this.addSerializer(AccessToken::class.java, AccessTokenSerializer())
        this.addDeserializer(AccessToken::class.java, AccessTokenDeserializer())
    }
}