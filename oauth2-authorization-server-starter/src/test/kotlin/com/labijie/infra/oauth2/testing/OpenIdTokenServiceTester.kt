package com.labijie.infra.oauth2.testing

import com.labijie.infra.oauth2.client.DefaultOAuth2ClientProviderService
import com.labijie.infra.oauth2.client.DefaultOpenIDConnectService
import com.labijie.infra.oauth2.client.InfraOAuth2CommonsProviders
import com.labijie.infra.oauth2.client.OAuth2ClientProviderNames
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.configuration.OAuth2ClientOidcLoginProperties
import kotlin.test.Test

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/22
 *
 */
class OpenIdTokenServiceTester {

    val appleIdToken = "eyJraWQiOiJVYUlJRlkyZlc0IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLnppeGlhZmVuZy52aXNpYyIsImV4cCI6MTc1MzI2MTUzNywiaWF0IjoxNzUzMTc1MTM3LCJzdWIiOiIwMDEzMjcuYzZlMDEzZTdiOTQzNDM2ZjhhZTFjOTYyYWJiNjdlMDEuMDgzNiIsImNfaGFzaCI6IkRYRVlRZ2dyd0lUSzdPVnA4elhxWnciLCJlbWFpbCI6IjI2NzU3MjcwQHFxLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdXRoX3RpbWUiOjE3NTMxNzUxMzcsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.saPKjryn2mlrsHM03xbB3Q04iNul6ORmHzLfUuDh8Fxx4uxmzKHWs1gdOgfXs55KSetGkP2zQD8pTEIFkwqDkK7aIH-N6hEGzBq8j7MZ34nNZh5hjlZK3j8ReSN6T_U-6gL8yW5SzbhAVj7FZXdt7BqFRBJYamL6de8hjbcRjWSXn2Dh0-BeUTATWU2ryCp4oU2W9XFfBHfPngctPKmiF5ovG7bYPNVevD43e8ZRQFnuMoaB4C56romxZZKJ6ohoSQEOB9ccTX331xNhhC9oC2BjUql8AWooJgFG69hu7kp7Y4B5UWF20LcYKrV-_eMth0hr4LWKFDnH0CrDYhnUDA"
    val appleAuthCode = "c55d518ccd0bf4aa981d808ca54e96b5c.0.srtsx.zuuGCQtAdE8S0qqkR6Aotw"

    val providers = mapOf(
        OAuth2ClientProviderNames.APPLE to InfraOAuth2CommonsProviders.Apple,
        OAuth2ClientProviderNames.DISCORD to InfraOAuth2CommonsProviders.Discord,
    )

    val properties by lazy {
        InfraOAuth2ClientProperties().apply {
            oidcLogin.putIfAbsent(OAuth2ClientProviderNames.APPLE, OAuth2ClientOidcLoginProperties.createFromProvider(InfraOAuth2CommonsProviders.Apple, setOf<String>()))
        }
    }

    @Test
    fun testAppleIDTokenDecoding() {
        val service = DefaultOpenIDConnectService(DefaultOAuth2ClientProviderService())
        val user = service.decodeToken(OAuth2ClientProviderNames.APPLE, appleIdToken, appleAuthCode, ignoreExpiration = true)

        assert(user.emailVerified == true)
        assert(!user.email.isNullOrBlank())
    }
}