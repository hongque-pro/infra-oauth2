package com.labijie.infra.oauth2.testing

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.annotation.EnableOAuth2Server
import com.labijie.infra.oauth2.annotation.OAuth2ServerType
import com.labijie.infra.oauth2.configuration.OAuth2CustomizationAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.testing.configuration.OAuth2TestAutoConfiguration
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.util.Base64Utils
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import kotlin.test.Test

@ContextConfiguration(classes = [
    OAuth2CustomizationAutoConfiguration::class,
    OAuth2ServerAutoConfiguration::class,
    OAuth2TestAutoConfiguration::class])
@WebMvcTest
@EnableOAuth2Server(OAuth2ServerType.Authorization)
class OAuth2ServerTester {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Throws(Exception::class)
    fun obtainAccessToken(username: String, password: String): String {
        val result: ResultActions = performTokenAction(username, password)
                .andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val resultString = result.andReturn().response.contentAsString
        val map = JacksonHelper.deserializeMap(resultString.toByteArray(Charsets.UTF_8), String::class, Any::class)
        val pretty = JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map)
        val json = map["access_token"].toString()
        logger.debug("Access token: ${System.lineSeparator()}$pretty")

        return json
    }

    private fun performTokenAction(username: String, password: String, clientId:String = "testClient", clientSecret: String = "abcdefg"): ResultActions {
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "password")
        params.add("scope", "api")
        params.add("username", username)
        params.add("password", password)
        return mockMvc.perform(post("/oauth/token")
                .params(params)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + Base64Utils.encodeToString("$clientId:$clientSecret".toByteArray(Charsets.UTF_8)))
                .accept(MediaType.APPLICATION_JSON))
    }

    @Test
    fun testCorrectPasswordLogin() {
        val token = this.obtainAccessToken("dummy-user", "11223344")
        Assertions.assertFalse(token.isBlank())
    }

    @Test
    fun testBadPasswordLogin() {
        val r = this.performTokenAction("dummy-user", "123456")
        r.andExpect(status().is4xxClientError)
    }

    @Test
    fun testBadClientSecretLogin() {
        val r = this.performTokenAction("dummy-user", "11223344", clientSecret = "1234455")
        r.andExpect(status().is4xxClientError)
    }
}