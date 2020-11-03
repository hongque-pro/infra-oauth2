package com.labijie.infra.oauth2.testing

import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.annotation.EnableOAuth2Server
import com.labijie.infra.oauth2.annotation.OAuth2ServerType
import com.labijie.infra.oauth2.configuration.OAuth2CustomizationAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ResourceServerAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.testing.abstraction.OAuth2Tester
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readAs
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.withBearerToken
import com.labijie.infra.oauth2.testing.configuration.OAuth2TestResServerAutoConfiguration
import com.labijie.infra.oauth2.testing.configuration.OAuth2TestServerAutoConfiguration
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.util.Base64Utils
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap

@ContextConfiguration(classes = [
    OAuth2CustomizationAutoConfiguration::class,
    OAuth2ServerAutoConfiguration::class,
    OAuth2ResourceServerAutoConfiguration::class,
    OAuth2TestResServerAutoConfiguration::class])
@WebMvcTest
@EnableOAuth2Server(OAuth2ServerType.Authorization, OAuth2ServerType.Resource)
class OAuth2ResourceServerTester : OAuth2Tester() {
    @Autowired
    override lateinit var mockMvc: MockMvc

    @Test
    fun testOneFactorAllow() {
        val token = this.obtainAccessToken()

        mockMvc.perform(MockMvcRequestBuilders.get("/test/1fac")
                .withBearerToken(token)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
    }

    @Test
    fun testTwoFactorReject() {
        val token = this.obtainAccessToken()

        mockMvc.perform(MockMvcRequestBuilders.get("/test/2fac")
                .withBearerToken(token)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
    }

    @Test
    fun testTwoFactorAllowed() {
        val token = this.obtainAccessToken()

        val result = mockMvc.perform(MockMvcRequestBuilders.post("/test/signin-2f")
                .withBearerToken(token)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap(true)
        val accessToken = map["access_token"]?.toString().orEmpty()

        mockMvc.perform(MockMvcRequestBuilders.get("/test/2fac")
                .withBearerToken(accessToken)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
    }

    private fun refreshToken(refreshTokenValue: String): String {
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "refresh_token")
        //params.add("scope", "api")
        params.add("refresh_token", refreshTokenValue)

        val result = mockMvc.perform(MockMvcRequestBuilders.post("/oauth/token")
                .params(params)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + Base64Utils.encodeToString("${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)))
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        val refreshedToken = (map["access_token"]?.toString()).orEmpty()
        Assertions.assertFalse(refreshedToken.isBlank())
        return refreshedToken
    }

    @Test
    fun testTwoFactorTokenRefresh() {
        val token = this.obtainAccessToken()

        //登录 2 段 token
        val result = mockMvc.perform(MockMvcRequestBuilders.post("/test/signin-2f")
                .withBearerToken(token)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap(true)
        val refreshTokenValue = map["refresh_token"]?.toString().orEmpty()

        val refreshedToken = refreshToken(refreshTokenValue)

        mockMvc.perform(MockMvcRequestBuilders.get("/test/2fac")
                .withBearerToken(refreshedToken)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
    }

    @Test
    fun testGetCurrentPrincipal() {
        val token = this.obtainAccessToken()

        val result = mockMvc.perform(MockMvcRequestBuilders.get("/test/current-user")
                .withBearerToken(token)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val principal = result.readToMap()
        Assertions.assertTrue(principal.containsKey(TwoFactorPrincipal::userId.name))
        Assertions.assertTrue(principal.containsKey(TwoFactorPrincipal::userName.name))
        Assertions.assertTrue(principal.containsKey(TwoFactorPrincipal::authorities.name))
        Assertions.assertTrue(principal.containsKey(TwoFactorPrincipal::attachedFields.name))
        Assertions.assertTrue(principal.containsKey(TwoFactorPrincipal::roleNames.name))
    }
}