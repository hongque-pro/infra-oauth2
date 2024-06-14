package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.configuration.DefaultClientProperties
import com.labijie.infra.utils.logger
import org.springframework.http.HttpHeaders
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import kotlin.reflect.KClass

object OAuth2TestingUtils {
        private val defaultClient = DefaultClientProperties()

        const val TestUserNme = "testUser"
        const val TestUserPassword = "pass0rd"
        val TestClientId = defaultClient.clientId
        val TestClientSecret = defaultClient.secret
        const val ResourceId = "test-resources"
        const val Scope = "test-scope"

        fun ResultActions.readToMap(logResult: Boolean = true): Map<String, Any> {
                val resultString = this.andReturn().response.contentAsString
                if(resultString.isNotBlank()) {
                        val map = JacksonHelper.deserializeMap(
                                resultString.toByteArray(Charsets.UTF_8),
                                String::class,
                                Any::class
                        )
                        val pretty = JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter()
                                .writeValueAsString(map)
                        if (logResult) {
                                logger.info("Http Result: ${System.lineSeparator()}$pretty")
                        }
                        return map
                }
                return mapOf()
        }

        fun <T: Any> ResultActions.readAs(type: KClass<T>): T {
                val resultString = this.andReturn().response.contentAsString
               return JacksonHelper.deserialize(resultString.toByteArray(Charsets.UTF_8), type)
        }

        fun MockHttpServletRequestBuilder.withBearerToken(token: String?): MockHttpServletRequestBuilder {
                if(token.isNullOrBlank()){
                        return this
                }
                return this.header(HttpHeaders.AUTHORIZATION, "Bearer $token")
        }
}