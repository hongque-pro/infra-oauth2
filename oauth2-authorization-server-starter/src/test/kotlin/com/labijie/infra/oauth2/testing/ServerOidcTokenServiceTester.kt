package com.labijie.infra.oauth2.testing

import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.component.DefaultOAuth2ServerRSAKeyPair
import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.oauth2.exception.InvalidIdTokenException
import com.labijie.infra.oauth2.service.DefaultOAuth2ServerOidcTokenService
import org.junit.jupiter.api.assertThrows
import java.lang.Thread.sleep
import java.time.Duration
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/1
 *
 */
class ServerOidcTokenServiceTester {

    private val properties = OAuth2ServerProperties()
    private val service = DefaultOAuth2ServerOidcTokenService(DefaultOAuth2ServerRSAKeyPair(properties), properties)

    fun assertOidcUsersEqual(expected: StandardOidcUser, actual: StandardOidcUser) {
        assertEquals(expected.provider, actual.provider, "provider mismatch")
        assertEquals(expected.userId, actual.userId, "userId mismatch")
        assertEquals(expected.email, actual.email, "email mismatch")
        assertEquals(expected.emailVerified, actual.emailVerified, "emailVerified mismatch")
        assertEquals(expected.emailHidden, actual.emailHidden, "emailHidden mismatch")
        assertEquals(expected.picture, actual.picture, "picture mismatch")
        assertEquals(expected.username, actual.username, "username mismatch")
        assertEquals(expected.registrationId, actual.registrationId, "registrationId mismatch")
    }

    private fun newUser(): StandardOidcUser {

        return StandardOidcUser(
            provider = "google",
            userId = UUID.randomUUID().toString(),
            email = "test@example.com",
            emailVerified = true,
            emailHidden = false,
            picture = "https://example.com/avatar.png",
            username = "testuser",
            registrationId = "reg123"
        )
    }

    @Test
    fun testCodec() {
        val user = newUser()
        val token = service.encode(user, expiration = Duration.ofMinutes(10))

        val decoded = service.decode(token, false)

        assertOidcUsersEqual(user, decoded)
    }

    @Test
    fun testDecodeExpired() {
        val user = newUser()
        val token = service.encode(user, expiration = Duration.ofMillis(10))

        sleep(100)

        assertThrows<InvalidIdTokenException> { service.decode(token, false) }
    }
}