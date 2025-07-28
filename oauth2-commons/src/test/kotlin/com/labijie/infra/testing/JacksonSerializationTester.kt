package com.labijie.infra.testing

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.labijie.infra.oauth2.serialization.jackson.OAuth2CommonsJacksonModule
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
class JacksonSerializationTester {
    val mapper = ObjectMapper().apply {
        registerModules(OAuth2CommonsJacksonModule())
    }

    inline fun <reified T> writeAndRead(value: T): T {
        val json = mapper.writeValueAsString(value)
        val restored = mapper.readValue<T>(json)
        return restored
    }

    @Test
    fun testOAuth2AuthorizationRequest() {
        // 构造 OAuth2AuthorizationRequest
        val original = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("https://discord.com/api/oauth2/authorize")
            .clientId("my-client-id")
            .redirectUri("https://myapp.com/login/oauth2/code/discord")
            .scopes(setOf("identify", "email"))
            .state("test-state-123")
            .attributes(mapOf("a1" to "a1_value", "a2" to "a2_value"))
            .additionalParameters(mapOf("prompt" to "consent"))
            .build()

        val restored = writeAndRead(original)

        // 验证：clientId 和 state 等字段一致
        assertEquals(original.clientId, restored.clientId)
        assertEquals(original.authorizationUri, restored.authorizationUri)
        assertEquals(original.redirectUri, restored.redirectUri)
        assertEquals(original.scopes, restored.scopes)
        assertEquals(original.state, restored.state)
        assertEquals(original.additionalParameters["prompt"], restored.additionalParameters["prompt"])
    }

    class SimpleValue<T> {
        var value: T? = null
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as SimpleValue<*>

            return value == other.value
        }

        override fun hashCode(): Int {
            return value?.hashCode() ?: 0
        }


    }

    @Test
    fun testAuthenticationMethod() {

        assertEquals(AuthenticationMethod.HEADER, writeAndRead(AuthenticationMethod.HEADER))

        val o1 = SimpleValue<AuthenticationMethod>()
        val v1 = writeAndRead(o1)

        assertEquals(o1, v1)


        val o2 = SimpleValue<AuthenticationMethod>().apply {
            value = AuthenticationMethod.FORM
        }
        val v2 = writeAndRead(o2)

        assertEquals(o2, v2)
    }
}