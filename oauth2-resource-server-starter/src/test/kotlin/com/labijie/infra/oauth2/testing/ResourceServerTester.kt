package com.labijie.infra.oauth2.testing

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.configuration.OAuth2CustomizationAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration
import com.labijie.infra.oauth2.testing.abstraction.OAuth2Tester
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readString
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.withBearerToken
import com.labijie.infra.oauth2.testing.configuration.ResourceServerTestingConfiguration
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import kotlin.test.Test

@ContextConfiguration(
    classes = [
        OAuth2CustomizationAutoConfiguration::class,
        OAuth2ServerAutoConfiguration::class,
        ResourceServerAutoConfiguration::class,
        ResourceServerTestingConfiguration::class,
    ]
)
@WebMvcTest
class ResourceServerTester : OAuth2Tester() {
    @Autowired
    override lateinit var mockMvc: MockMvc


    private fun performTokenValue(): String {
        val result = this.performTokenAction()
        return result.readTokenValue()
    }

    private fun ResultActions.readTokenValue(): String {
        val tokenResult = this.readToMap()
        logger.info(System.lineSeparator() + JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(tokenResult))
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tv = tokenResult["access_token"]?.toString()

        Assertions.assertTrue(!tv.isNullOrBlank(), "access_token can not be null or blank")
        return tv.orEmpty()
    }

    private fun performPost(tokenValue: String, url: String, jsonResponseAssertion: Boolean = true): ResultActions {
        return mockMvc.perform(
            post(url)
                .withBearerToken(tokenValue)
                .accept(MediaType.APPLICATION_JSON)
        )
            .let {
                if (jsonResponseAssertion) {
                    it.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                }else{
                    it
                }
            }
    }

    private fun performGet(tokenValue: String, url: String, jsonResponseAssertion: Boolean = true): ResultActions {
        return mockMvc.perform(
            get(url)
                .withBearerToken(tokenValue)
                .accept(MediaType.APPLICATION_JSON)
        )
            .let {
                if (jsonResponseAssertion) {
                    it.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                }else{
                    it
                }
            }
    }

    @Test
    fun test1FactoAccess() {
        val tokenValue = performTokenValue()
        val result = performGet(tokenValue, "/test/1fac").andExpect(status().isOk)
        val r = result.readString()
        Assertions.assertEquals("ok", r)
    }

    @Test
    fun test2FactorDenied() {
        val tokenValue = performTokenValue()
        performGet(tokenValue, "/test/2fac", false).andExpect {
            status().`is`(403)
        }
    }

    @Test
    fun test2FactorAllow() {
        val tokenValue = performTokenValue()

        val twoFactorTokenValue = performPost(tokenValue,"/test/sign-2f").readTokenValue()
        performGet(twoFactorTokenValue, "/test/2fac").andExpect {
            status().isOk
        }
    }


}