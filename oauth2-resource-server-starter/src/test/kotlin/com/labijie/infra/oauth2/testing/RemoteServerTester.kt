package com.labijie.infra.oauth2.testing

import com.labijie.dummy.auth.DummyConstants
import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.OAuth2Constants
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.testing.configuration.EventTestSubscription
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.assertNotNull
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.client.ClientHttpResponse
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.ResponseErrorHandler
import org.springframework.web.client.RestClient
import org.springframework.web.client.toEntity
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals


class RemoteServerTester() {

    companion object {
        private fun <T> ResponseEntity<T>.assertOk(): ResponseEntity<T> {
            assert(this.statusCode.value() == 200 ) { "Excepted status ok, but got ${this.statusCode}\n\nbody: ${this.body}" }
            return this
        }

        private fun <T> ResponseEntity<T>.assert4xxClientError(): ResponseEntity<T> {
            assert(this.statusCode.is4xxClientError) { "Excepted status 4xx, but got ${this.statusCode}\n\nbody: ${this.body}" }
            return this
        }

        private fun <T> ResponseEntity<T>.assetStatus(status: HttpStatus): ResponseEntity<T> {
            assertEquals(status.value(), this.statusCode.value(), "Excepted status ${status.value()}, but got ${this.statusCode.value()}\n\nbody: ${this.body}")
            return this
        }

        private fun <T> ResponseEntity<T>.assetStatus(code: Int): ResponseEntity<T> {
            assertEquals(code, this.statusCode.value(), "Excepted status ${code}, but got ${this.statusCode.value()}\n\nbody: ${this.body}")
            return this
        }
    }

    private object NoErrorHandler : ResponseErrorHandler {
        override fun hasError(response: ClientHttpResponse): Boolean {
            return false
        }
    }

    private val resetClient = RestClient.builder().defaultStatusHandler(NoErrorHandler).baseUrl("http://localhost:8088").build()

    protected val defaultOAuth2ServerSettings = AuthorizationServerSettings.builder().build()

    private fun ResponseEntity<String>.readToMap(logResult: Boolean = true): Map<String, Any> {
        val body = this.body
        return body?.let {
            val map = JacksonHelper.deserializeMap(body.toByteArray(Charsets.UTF_8), String::class, Any::class)
            if (logResult) {
                val pretty = JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map)
                val log = arrayOf(System.lineSeparator(), "[Json Response]", pretty).joinToString(System.lineSeparator())
                logger.debug(log)
            }
            map
        } ?: emptyMap()
    }



    @Throws(Exception::class)
    private fun obtainAccessToken(username: String = DummyConstants.username, password: String = DummyConstants.userPassword): String? {
        val result = performTokenAction(username, password)

        val map = result.readToMap()
        val json = map["access_token"]?.toString()

        logger.debug(System.lineSeparator() + JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map))
        return json
    }

    private fun performTokenAction(
        username: String = DummyConstants.username,
        password: String = DummyConstants.userPassword,
        clientId: String = DummyConstants.clientId,
        clientSecret: String = DummyConstants.clientSecret): ResponseEntity<String> {


        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "password")
        params.add("scope", DummyConstants.scope)
        params.add("username", username)
        params.add("password", password)

        EventTestSubscription.resetFireCount()
        val resp = try {
            resetClient.post().uri {
                it.path(defaultOAuth2ServerSettings.tokenEndpoint)
                    .queryParam("grant_type", "password")
                    .queryParam("scope", DummyConstants.scope)
                    .queryParam("username", username)
                    .queryParam("password", password)
                    .build()
            }
                .header(
                    HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString("$clientId:$clientSecret".toByteArray(Charsets.UTF_8))
                )
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .toEntity<String>()
        } catch (e: HttpClientErrorException) {
            ResponseEntity<String>.status(e.statusCode).body(e.getResponseBodyAsString(Charsets.UTF_8))
        }

        resp.assertOk()

        return resp
    }

    private fun performTokenValue(): String {
        val result = this.performTokenAction()
        val b = result.body
        assertNotNull(b, "Access token response was null")
        return result.readToMap(false)["access_token"] as String
    }

    private fun performPost(path: String, tokenValue: String? = null): ResponseEntity<String> {
        return try {
            val resp = resetClient.post().uri {
                it.path(path).build()
            }
                .apply {
                    tokenValue?.let {
                        header(HttpHeaders.AUTHORIZATION, "Bearer $tokenValue")
                    }
                }
                .retrieve()
                .toEntity<String>()

            resp
        } catch (e: HttpClientErrorException) {
            ResponseEntity<String>.status(e.statusCode).body(e.getResponseBodyAsString(Charsets.UTF_8))
        }
    }

    private fun performGet(path: String, tokenValue: String? = null): ResponseEntity<String> {
        return try {
            val resp = resetClient.get().uri {
                it.path(path).build()
            }
                .apply {
                    tokenValue?.let {
                        header(HttpHeaders.AUTHORIZATION, "Bearer $tokenValue")
                    }
                }
                .retrieve()
                .toEntity<String>()

            resp
        } catch (e: HttpClientErrorException) {
            ResponseEntity<String>.status(e.statusCode).body(e.getResponseBodyAsString(Charsets.UTF_8))
        }
    }

    @Test
    fun tokeRequiredAccess() {
        val result = performGet("/test/1fac")
        assert(result.statusCode.is4xxClientError)
        val map = result.readToMap()
        assertEquals(map["error"], "access_denied")
    }

    @Test
    fun test1FactoAccess() {
        val tokenValue = performTokenValue()
        val result = performGet("/test/1fac", tokenValue).assertOk()
        Assertions.assertEquals("ok", result.body)
    }

    @Test
    fun testBadAccessToken() {
        val result = performGet("/test/1fac", UUID.randomUUID().toString()).assert4xxClientError()

        val map = result.readToMap()
        val errorCode = map["error"]?.toString()
        assertEquals(OAuth2ErrorCodes.INVALID_TOKEN, errorCode)
    }

    @Test
    fun test2FactorDenied() {
        val tokenValue = performTokenValue()
        performGet("/test/2fac", tokenValue).assetStatus(403)
    }

    @Test
    fun test2FactorAllow() {
        val tokenResult = this.performTokenAction()
        val tokenMap = tokenResult.readToMap(true)

        val tokenValue = tokenMap["access_token"]?.toString()

        assertNotNull(tokenValue)

        val twoFactorToken = performPost("/test/sign-2f", tokenValue)
        val twoFacTokenMap = twoFactorToken.readToMap(true)

        Assertions.assertTrue(twoFacTokenMap[OAuth2Constants.CLAIM_TWO_FACTOR] as Boolean)

        val diffrentKeys = arrayOf(
            OAuth2Constants.CLAIM_JTI,
            OAuth2ParameterNames.EXPIRES_IN,
            OAuth2ParameterNames.REFRESH_TOKEN,
            OAuth2ParameterNames.ACCESS_TOKEN,
            OAuth2Constants.CLAIM_TWO_FACTOR
        )

        tokenMap.forEach { (k, v) ->
            val newValue = twoFacTokenMap[k]
            assertNotNull(newValue) { "two factor token missed filed: '$k' " }
            if (k !in diffrentKeys) {
                assertEquals(v, newValue, "two factor token change filed: '$k' ")
            }
        }

        Assertions.assertEquals(tokenMap.size + 1, twoFacTokenMap.size, "Two factor fields changed !")

        val twoFactorTokenValue = twoFactorToken.readToMap()["access_token"]?.toString()
        assertNotNull(twoFactorTokenValue)

        performGet("/test/2fac", twoFactorTokenValue).assertOk()
    }

    @Test
    fun testHasTokenAttributeValue() {
        val tokenValue = this.performTokenValue()

        val ok = performPost("/test/field-aaa-test", tokenValue).assertOk()

        Assertions.assertEquals("ok", ok.body)

        performPost("/test/field-bbb-test", tokenValue).assetStatus(403)
    }

    @Test
    fun testHasRole() {
        val tokenValue = this.performTokenValue()

        val ok = performPost("/test/role-aa-test", tokenValue).assertOk()

        assertEquals("ok", ok.body)

        performPost("/test/role-bb-test", tokenValue).assetStatus(403)
    }



    @Test
    fun testPrincipal() {
        val tokenValue = this.performTokenValue()


        val p = performGet("/test/current-user", tokenValue).assertOk().readToMap()

        Assertions.assertNotNull(p)
        Assertions.assertEquals(
            OAuth2TestingUtils.TestUser.authorities.size,
            (p[TwoFactorPrincipal::authorities.name] as List<*>).size
        )

        val first = (p[TwoFactorPrincipal::authorities.name] as List<*>).first() as Map<*, *>
        Assertions.assertEquals(OAuth2TestingUtils.TestUser.authorities.first().authority, first["authority"])

        val attachedFields = p[TwoFactorPrincipal::attachedFields.name] as Map<*, *>
        Assertions.assertNotNull(attachedFields, "attachedFields missed")
        OAuth2TestingUtils.TestUser.getTokenAttributes().forEach { (t, u) ->
            Assertions.assertTrue(attachedFields.containsKey(t))
            Assertions.assertEquals(u, attachedFields[t]?.toString())
        }
    }
}