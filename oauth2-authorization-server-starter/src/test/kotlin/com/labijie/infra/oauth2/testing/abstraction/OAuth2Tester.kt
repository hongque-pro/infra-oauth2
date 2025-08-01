package com.labijie.infra.oauth2.testing.abstraction

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import com.labijie.infra.oauth2.testing.configuration.EventTestSubscription
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import java.util.*
import kotlin.test.assertEquals

abstract class OAuth2Tester {

    protected abstract val mockMvc: MockMvc

    protected val defaultOAuth2ServerSettings = AuthorizationServerSettings.builder().build()

    @Throws(Exception::class)
    protected fun obtainAccessToken(username: String = OAuth2TestingUtils.TestUserName, password: String = OAuth2TestingUtils.TestUserPassword): String? {
        val result: ResultActions = performTokenAction(username, password)
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        val json = map["access_token"]?.toString()

        val aud = map[OAuth2TokenClaimNames.AUD]
        assert(aud is Collection<*>)

        assert((aud as Collection<*>).contains(OAuth2TestingUtils.TestClientId))
        assertEquals(OAuth2TestingUtils.TestUserName, map[OAuth2TokenClaimNames.SUB])

        logger.debug(System.lineSeparator() + JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
        return json
    }



    protected fun performTokenAction(username: String = OAuth2TestingUtils.TestUserName, password: String = OAuth2TestingUtils.TestUserPassword, clientId: String = OAuth2TestingUtils.TestClientId, clientSecret: String = OAuth2TestingUtils.TestClientSecret): ResultActions {
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "password")
        params.add("scope", OAuth2TestingUtils.Scope)
        params.add("username", username)
        params.add("password", password)

        EventTestSubscription.resetFireCount()
        val result = mockMvc.perform(MockMvcRequestBuilders.post(defaultOAuth2ServerSettings.tokenEndpoint)
                .params(params)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + Base64.getEncoder().encodeToString("$clientId:$clientSecret".toByteArray(Charsets.UTF_8)))
                .accept(MediaType.APPLICATION_JSON))

        result.andExpect {
            if(it.response.status == HttpStatus.OK.value()){
                Assertions.assertEquals(1, EventTestSubscription.fireCount.get())
            }
        }
        return result
    }
}