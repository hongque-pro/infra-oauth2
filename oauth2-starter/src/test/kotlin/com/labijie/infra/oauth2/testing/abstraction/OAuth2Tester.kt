package com.labijie.infra.oauth2.testing.abstraction

import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.util.Base64Utils
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap

abstract class OAuth2Tester {

    protected abstract val mockMvc: MockMvc

    @Throws(Exception::class)
    protected fun obtainAccessToken(username: String = OAuth2TestingUtils.TestUserNme, password: String = OAuth2TestingUtils.TestUserPassword): String? {
        val result: ResultActions = performTokenAction(username, password)
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))

        val map = result.readToMap()
        val json = map["access_token"]?.toString()

        return json
    }



    protected fun performTokenAction(username: String = OAuth2TestingUtils.TestUserNme, password: String = OAuth2TestingUtils.TestUserPassword, clientId: String = OAuth2TestingUtils.TestClientId, clientSecret: String = OAuth2TestingUtils.TestClientSecret): ResultActions {
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "password")
        params.add("scope", OAuth2TestingUtils.ResourceId)
        params.add("username", username)
        params.add("password", password)
        return mockMvc.perform(MockMvcRequestBuilders.post("/oauth/token")
                .params(params)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + Base64Utils.encodeToString("$clientId:$clientSecret".toByteArray(Charsets.UTF_8)))
                .accept(MediaType.APPLICATION_JSON))
    }
}