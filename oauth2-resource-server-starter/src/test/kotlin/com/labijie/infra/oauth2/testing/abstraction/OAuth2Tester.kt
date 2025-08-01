package com.labijie.infra.oauth2.testing.abstraction

import com.labijie.dummy.auth.DummyConstants
import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.OAuth2Constants
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import com.labijie.infra.oauth2.testing.configuration.EventTestSubscription
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import java.util.*

abstract class OAuth2Tester {

    protected abstract val mockMvc: MockMvc

    protected val defaultOAuth2ServerSettings = AuthorizationServerSettings.builder().build()

    @Throws(Exception::class)
    protected open fun obtainAccessToken(
        username: String = DummyConstants.username,
        password: String = DummyConstants.userPassword
    ): String? {
        val result: ResultActions = performTokenAction(username, password)
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        val json = map["access_token"]?.toString()

        logger.debug(
            System.lineSeparator() + JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(map)
        )
        return json
    }


    protected open fun performTokenAction(
        username: String = DummyConstants.username,
        password: String = DummyConstants.userPassword,
        clientId: String = DummyConstants.clientId,
        clientSecret: String = DummyConstants.clientSecret
    ): ResultActions {
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "password")
        params.add("scope", DummyConstants.scope)
        params.add("username", username)
        params.add("password", password)

        EventTestSubscription.resetFireCount()
        val result = mockMvc.perform(
            MockMvcRequestBuilders.post(defaultOAuth2ServerSettings.tokenEndpoint)
                .params(params)
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString("$clientId:$clientSecret".toByteArray(Charsets.UTF_8))
                )
                .accept(MediaType.APPLICATION_JSON)
        )

        result.andExpect {
            if (it.response.status == HttpStatus.OK.value()) {
                Assertions.assertEquals(1, EventTestSubscription.fireCount.get())
            }
        }
        return result
    }
}