package com.labijie.infra.oauth2.testing

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.IOAuth2ServerJwtCodec
import com.labijie.infra.oauth2.OAuth2Constants
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.testing.abstraction.OAuth2Tester
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.withBearerToken
import com.labijie.infra.oauth2.testing.configuration.OAuth2TestServerAutoConfiguration
import com.labijie.infra.utils.ShortId
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.ImportAutoConfiguration
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


@WebMvcTest
@ContextConfiguration(classes = [OAuth2TestServerAutoConfiguration::class])
@ImportAutoConfiguration(classes = [SecurityFilterAutoConfiguration::class])
class OAuth2ServerTester : OAuth2Tester() {
    @Autowired
    override lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var jwtDecoder: IOAuth2ServerJwtCodec

    @Test
    fun testCorrectPasswordLogin() {
        val token = this.obtainAccessToken()
        Assertions.assertFalse(token.isNullOrBlank())
    }

    @Test
    fun testBadPasswordLogin() {
        val r = this.performTokenAction(password = "!@#@$###GD")
        r.andExpect(status().is4xxClientError)

        val json = r.readToMap()
        assertEquals(json["error"], OAuth2ErrorCodes.INVALID_GRANT)
    }

    @Test
    fun testBadClientSecretLogin() {
        val r = this.performTokenAction(clientSecret = "abcdefg")
        r.andExpect(status().is4xxClientError)
    }


    @Test
    fun testBadRefreshToken() {
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "refresh_token")
        //params.add("scope", "api")
        params.add("refresh_token", UUID.randomUUID().toString())
        val result = mockMvc.perform(
            post(defaultOAuth2ServerSettings.tokenEndpoint)
                .params(params)
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(
                        "${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)
                    )
                )
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().is4xxClientError)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        val errorCode = map["error"]?.toString()
        Assertions.assertEquals(OAuth2ErrorCodes.INVALID_GRANT, errorCode)
    }

    @Test
    fun testSignInHelper() {

//        mockMvc.perform(
//            get("/access")
//                .accept(MediaType.APPLICATION_JSON)
//        )
//        .andExpect(status().is4xxClientError)

        val result = mockMvc.perform(
            post("/fake-login")
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        assert(map.containsKey("access_token"))
        assert(map.containsKey("refresh_token"))

        mockMvc.perform(
            get("/access").withBearerToken(map["access_token"]!!.toString())
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)

        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "refresh_token")
        //params.add("scope", "api")
        params.add("refresh_token", map["refresh_token"]?.toString())

        mockMvc.perform(
            post(defaultOAuth2ServerSettings.tokenEndpoint)
                .params(params)
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(
                        "${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)
                    )
                )
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

    }

    @Test
    fun testRefreshToken() {
        val tokenResult = this.performTokenAction().readToMap(action = "Request Token")

        assertNotNull(tokenResult["access_token"])

        val accessToken = tokenResult["access_token"].toString()

        Assertions.assertTrue(tokenResult.containsKey("refresh_token"))
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "refresh_token")
        //params.add("scope", "api")
        params.add("refresh_token", tokenResult["refresh_token"]?.toString())

        val result = mockMvc.perform(
            post(defaultOAuth2ServerSettings.tokenEndpoint)
                .params(params)
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(
                        "${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)
                    )
                )
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap(action = "Refresh Token")
        val refreshedToken = map["access_token"]?.toString()
        assertNotNull(refreshedToken)
        doCheckToken(map["access_token"]!!.toString())

        assetTokenEquals(accessToken, refreshedToken)
    }

    private fun assetTokenEquals(
        originToken: String,
        refreshedToken: String,
    ) {

        val at = jwtDecoder.decode(originToken)
        val newAt = jwtDecoder.decode(refreshedToken)
        assertEquals(at.claims.size, newAt.claims.size)

        //不相同的比进行比较
        val diffClaims = arrayOf(JwtClaimNames.JTI, JwtClaimNames.NBF, JwtClaimNames.EXP, JwtClaimNames.IAT)

        at.claims.forEach { (key, _) ->
            if (!diffClaims.contains(key)) {
                assertEquals(at.claims[key], newAt.claims[key], "Claim '${key}' is not equals after refresh token")
            } else {
                assertTrue(newAt.claims.containsKey(key), "'${key}' is missed while token refreshed.")
            }
        }
    }

    @Test
    fun testCheckToken() {
        val tokenResult = this.performTokenAction().readToMap()
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tokenValue = tokenResult["access_token"]?.toString()

        val map = doCheckToken(tokenValue)

        logger.debug(JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
    }

    @Test
    fun testRevocation() {
        val tokenResult = this.performTokenAction().readToMap()
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tokenValue = tokenResult["access_token"]?.toString()
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("token", tokenValue)
        params.add("token_type_hint", "Bearer")

        val r = mockMvc.perform(
            post("/oauth2/revoke")
                .params(params)
                .contentType(MediaType.APPLICATION_JSON)
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(
                        "${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)
                    )
                )
        )
            .andExpect(status().isOk)

        r.readToMap()
    }

    @Test
    fun introspectTest() {
        val tokenResult = this.performTokenAction().readToMap()
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tokenValue = tokenResult["access_token"]?.toString()

        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("token", tokenValue)
        params.add("token_type_hint", "Bearer")

        val result = mockMvc.perform(
            post(OAuth2Constants.ENDPOINT_INTROSPECT)
                .params(params)
                .contentType(MediaType.APPLICATION_JSON)
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(
                        "${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)
                    )
                )
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        Assertions.assertEquals(map["active"]?.toString(), "true")
    }

    private fun doCheckToken(tokenValue: String?): Map<String, Any> {
        val result = mockMvc.perform(
            post(OAuth2Constants.ENDPOINT_CHECK_TOKEN)
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
    fun testCheckBadToken() {
        val result = mockMvc.perform(
            post(OAuth2Constants.ENDPOINT_CHECK_TOKEN)
                .param("token", ShortId.newId())
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().`is`(200))
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        Assertions.assertEquals(map["active"]?.toString(), "false")
    }

    @Test
    fun testIntrospectEndpoint() {
        val tokenResult = this.performTokenAction().readToMap()
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tokenValue = tokenResult["access_token"]?.toString()

        val result = mockMvc.perform(
            post(defaultOAuth2ServerSettings.tokenIntrospectionEndpoint)
                .param("token", tokenValue)
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(
                        "${OAuth2TestingUtils.TestClientId}:${OAuth2TestingUtils.TestClientSecret}".toByteArray(Charsets.UTF_8)
                    )
                )
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        //Assertions.assertEquals(map["active"]?.toString(), "true")

        logger.debug(JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
    }

    @Test
    fun testJwkSetEndpoint() {
        val result = mockMvc.perform(
            get(defaultOAuth2ServerSettings.jwkSetEndpoint)
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))


        logger.debug(RsaUtils.defaultKeyPair.public.toString())

        val map = result.readToMap()
        //Assertions.assertEquals(map["active"]?.toString(), "true")

        logger.debug(JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
    }

}