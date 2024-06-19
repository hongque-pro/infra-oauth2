package com.labijie.infra.oauth2.testing

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.OAuth2AuthorizationConverter
import com.labijie.infra.oauth2.serialization.jackson.OAuth2JacksonModule
import com.labijie.infra.oauth2.testing.component.TestingIdentityService
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.jackson2.CoreJackson2Module
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import kotlin.test.Test
import kotlin.test.assertEquals

class ITwofactorUSerDetailsSerializationTester {


    val testUer = TestingIdentityService().getUserByName("SerTester")


    private fun writeMap(data: Map<String, Any>): String {
        return try {
            OAuth2AuthorizationConverter.Instance.objectMapper.writeValueAsString(data)
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    private fun readMap(data: String): Map<String, Any> {
        if (data.isBlank()) {
            return mapOf()
        }
        return try {
            OAuth2AuthorizationConverter.Instance.objectMapper.readValue(data, object : TypeReference<Map<String, Any>>() {})
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    @Test
    fun testSerialize(){
        val testData = mapOf<String, Any>(
            "a" to "1234556",
            "b" to 123456,
            "c" to testUer
        )
        val json = OAuth2AuthorizationConverter.Instance.objectMapper.writeValueAsBytes(testData)
    }

    @Test
    fun deserializeMap(){
        val principal = UsernamePasswordAuthenticationToken(testUer, "PROTE")
        val json = OAuth2AuthorizationConverter.Instance.objectMapper.writeValueAsBytes(principal)
//        val file = this.javaClass.getResourceAsStream("/test.json")
//        val json = file.readBytes().toString(Charsets.UTF_8)
//        val map = readMap(json)
        val v = OAuth2AuthorizationConverter.Instance.objectMapper.readValue(json, UsernamePasswordAuthenticationToken::class.java)
        assertEquals(principal.principal::class.java, v.principal::class.java)
        assertEquals(principal.credentials, principal.credentials)
    }
}