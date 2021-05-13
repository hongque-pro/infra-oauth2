package com.labijie.infra.oauth2.testing

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.Constants.DEFAULT_JWK_SET_ENDPOINT_PATH
import com.labijie.infra.oauth2.Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH
import com.labijie.infra.oauth2.configuration.OAuth2CustomizationAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.testing.abstraction.OAuth2Tester
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import com.labijie.infra.oauth2.testing.configuration.EventTestSubscription
import com.labijie.infra.oauth2.testing.configuration.OAuth2TestServerAutoConfiguration
import com.labijie.infra.utils.ShortId
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
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
    OAuth2TestServerAutoConfiguration::class])
@WebMvcTest
class OAuth2ServerTester : OAuth2Tester() {
    @Autowired
    override lateinit var mockMvc: MockMvc

    @Test
    fun testCorrectPasswordLogin() {
        val token = this.obtainAccessToken()
        Assertions.assertFalse(token.isNullOrBlank())
    }

    @Test
    fun testBadPasswordLogin() {
        EventTestSubscription
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

        doCheckToken(map["access_token"]!!.toString())
    }

    @Test
    fun testCheckToken(){
        val tokenResult = this.performTokenAction().readToMap()
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tokenValue = tokenResult["access_token"]?.toString()

        val map = doCheckToken(tokenValue)

        logger.debug(JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
    }

    private fun doCheckToken(tokenValue: String?): Map<String, Any> {
        val result = mockMvc.perform(
            post("/oauth/check_token")
                .param("token", tokenValue)
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        Assertions.assertEquals(map["active"]?.toString(), "true")
        return map
    }

    @Test
    fun testCheckBadToken(){
        val result = mockMvc.perform(post("/oauth/check_token")
                .param("token", ShortId.newId())
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().`is`(400))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        logger.debug(JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
    }

    @Test
    fun testIntrospectEndpoint(){
        val tokenResult = this.performTokenAction().readToMap()
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tokenValue = tokenResult["access_token"]?.toString()

        val result = mockMvc.perform(post(DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH)
                .param("token", tokenValue)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + Base64Utils.encodeToString("${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)))
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        //Assertions.assertEquals(map["active"]?.toString(), "true")

        logger.debug(JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
    }

    @Test
    fun testJwkSetEndpoint(){
        val result = mockMvc.perform(get(DEFAULT_JWK_SET_ENDPOINT_PATH)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        //Assertions.assertEquals(map["active"]?.toString(), "true")

        logger.debug(JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
    }
}