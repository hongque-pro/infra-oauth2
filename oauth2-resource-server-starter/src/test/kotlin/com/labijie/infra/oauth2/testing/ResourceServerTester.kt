package com.labijie.infra.oauth2.testing

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.configuration.OAuth2CustomizationAutoConfiguration
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration
import com.labijie.infra.oauth2.testing.abstraction.OAuth2Tester
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readString
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readToMap
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.readTokenValue
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils.withBearerToken
import com.labijie.infra.oauth2.testing.configuration.ResourceServerTestingConfiguration
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.security.oauth2.common.OAuth2AccessToken
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



    private fun performPost(tokenValue: String, url: String, jsonResponseAssertion: Boolean = true): ResultActions {
        return mockMvc.perform(
                post(url)
                        .withBearerToken(tokenValue)
                        .accept(MediaType.APPLICATION_JSON)
        )
                .let {
                    if (jsonResponseAssertion) {
                        it.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    } else {
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
                    } else {
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
        val tokenResult = this.performTokenAction()
        val tokenMap = tokenResult.readToMap(true)

        //Assertions.assertFalse(tokenMap[Constants.CLAIM_TWO_FACTOR] as Boolean)

        val tokenValue = tokenResult.readTokenValue()
        val twoFactorToken = performPost(tokenValue, "/test/sign-2f")
        val twoFacTokenMap = twoFactorToken.readToMap(true)

        Assertions.assertTrue(twoFacTokenMap[Constants.CLAIM_TWO_FACTOR] as Boolean)

        val diffrentKeys = arrayOf(
                Constants.CLAIM_JTI,
                OAuth2AccessToken.EXPIRES_IN,
                OAuth2AccessToken.REFRESH_TOKEN,
                OAuth2AccessToken.ACCESS_TOKEN,
                Constants.CLAIM_TWO_FACTOR)

        tokenMap.forEach { (k, v) ->
            val newValue = twoFacTokenMap[k]
            Assertions.assertNotNull(newValue, "two factor token missed filed: '$k' ")
            if (k !in diffrentKeys) {
                Assertions.assertEquals(v, newValue, "two factor token change filed: '$k' ")
            }
        }

        Assertions.assertEquals(tokenMap.size, twoFacTokenMap.size, "two factor has more fields")

        val twoFactorTokenValue = twoFactorToken.readTokenValue()
        performGet(twoFactorTokenValue, "/test/2fac").andExpect {
            status().isOk
        }

    }

    @Test
    fun testHasTokenAttributeValue() {
        val tokenValue = this.performTokenValue()

        val ok = performPost(tokenValue, "/test/field-aaa-test").andExpect {
            status().isOk
        }

        Assertions.assertEquals("ok", ok.readString(false))

        performPost(tokenValue, "/test/field-bbb-test", false).andExpect {
            status().`is`(403)
        }

    }
}