package com.labijie.infra.oauth2.testing

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.annotation.EnableOAuth2Server
import com.labijie.infra.oauth2.annotation.OAuth2ServerType
import com.labijie.infra.oauth2.configuration.OAuth2CustomizationAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
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
    fun obtainAccessToken(username: String = OAuth2TestingUtils.TestUserNme, password: String = OAuth2TestingUtils.TestUserPassword): String? {
        val result: ResultActions = performTokenAction(username, password)
                .andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        val json = map["access_token"]?.toString()

        return json
    }



    private fun performTokenAction(username: String = OAuth2TestingUtils.TestUserNme, password: String = OAuth2TestingUtils.TestUserPassword, clientId:String =OAuth2TestingUtils.TestClientId, clientSecret: String = OAuth2TestingUtils.TestClientSecret): ResultActions {
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
        val token = this.obtainAccessToken()
        Assertions.assertFalse(token.isNullOrBlank())
    }

    @Test
    fun testBadPasswordLogin() {
        val r = this.performTokenAction(password = "!@#@$###GD")
        r.andExpect(status().is4xxClientError)
    }

    @Test
    fun testBadClientSecretLogin() {
        val r = this.performTokenAction(clientSecret = "abcdefg")
        r.andExpect(status().is4xxClientError)
    }

    @Test
    fun testRefreshToken(){
        val tokenResult = this.performTokenAction().readToMap()
        Assertions.assertTrue(tokenResult.containsKey("refresh_token"))

        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "refresh_token")
        //params.add("scope", "api")
        params.add("refresh_token", tokenResult["refresh_token"]?.toString())

        val result = mockMvc.perform(post("/oauth/token")
                .params(params)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + Base64Utils.encodeToString("${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)))
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        val refreshedToken = map["access_token"]?.toString()
        Assertions.assertFalse(refreshedToken.isNullOrBlank())
    }
}