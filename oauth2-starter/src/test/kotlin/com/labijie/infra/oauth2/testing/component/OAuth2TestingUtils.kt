package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.utils.logger
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.test.web.servlet.ResultActions

object OAuth2TestingUtils {
        val passwordEncoder = BCryptPasswordEncoder()

        const val TestUserNme = "testUser"
        const val TestUserPassword = "pass0rd"
        const val TestClientId = "testClient"
        const val TestClientSecret = "good@play"

        fun ResultActions.readToMap(logResult: Boolean = true): Map<String, Any> {
                val resultString = this.andReturn().response.contentAsString
                val map = JacksonHelper.deserializeMap(resultString.toByteArray(Charsets.UTF_8), String::class, Any::class)
                val pretty = JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map)
                if(logResult) {
                        logger.debug("Http Result: ${System.lineSeparator()}$pretty")
                }
                return map
        }
}