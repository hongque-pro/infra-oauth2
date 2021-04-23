package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readAs
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.http.HttpHeaders
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import kotlin.reflect.KClass

object OAuth2TestingUtils {
    val passwordEncoder = BCryptPasswordEncoder()

    const val TestUserNme = "testUser"
    const val TestUserPassword = "pass0rd"
    const val TestClientId = "testClient"
    const val TestClientSecret = "good@play"
    const val ResourceId = "test-resources"
    const val Scope = "test-scope"

    fun ResultActions.readToMap(logResult: Boolean = true): Map<String, Any> {
        val resultString = this.andReturn().response.contentAsString
        val map = JacksonHelper.deserializeMap(resultString.toByteArray(Charsets.UTF_8), String::class, Any::class)
        if (logResult) {
            val pretty = JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map)
            val url = this.andReturn().request.requestURI
            val log = arrayOf(System.lineSeparator(), url, "[Json Response]", pretty).joinToString(System.lineSeparator())
            logger.debug(log)
        }
        return map
    }

    fun ResultActions.readTokenValue(): String {
        val tokenResult = this.readToMap()
        logger.info(System.lineSeparator() + JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(tokenResult))
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tv = tokenResult["access_token"]?.toString()

        Assertions.assertTrue(!tv.isNullOrBlank(), "access_token can not be null or blank")
        return tv.orEmpty()
    }

    fun ResultActions.readString(logResult: Boolean = true): String {
        val s = this.andReturn().response.contentAsString

        if (logResult) {
            logger.info("Http Result: ${System.lineSeparator()}$s")
        }
        return s
    }

    fun <T : Any> ResultActions.readAs(type: KClass<T>): T {
        val resultString = this.andReturn().response.contentAsString
        return JacksonHelper.deserialize(resultString.toByteArray(Charsets.UTF_8), type)
    }

    fun MockHttpServletRequestBuilder.withBearerToken(token: String?): MockHttpServletRequestBuilder {
        if (token.isNullOrBlank()) {
            return this
        }
        return this.header(HttpHeaders.AUTHORIZATION, "Bearer $token")
    }
}