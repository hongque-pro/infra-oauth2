package com.labijie.infra.oauth2.testing

import com.labijie.infra.oauth2.client.OpenIdJwtDecoder
import com.labijie.infra.oauth2.client.apple.toAppleIdToken
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/22
 *
 */
class OpenIdJwtDecoderTester {

    val appleIdToken = "eyJraWQiOiJVYUlJRlkyZlc0IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLnppeGlhZmVuZy52aXNpYyIsImV4cCI6MTc1MzI2MTUzNywiaWF0IjoxNzUzMTc1MTM3LCJzdWIiOiIwMDEzMjcuYzZlMDEzZTdiOTQzNDM2ZjhhZTFjOTYyYWJiNjdlMDEuMDgzNiIsImNfaGFzaCI6IkRYRVlRZ2dyd0lUSzdPVnA4elhxWnciLCJlbWFpbCI6IjI2NzU3MjcwQHFxLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdXRoX3RpbWUiOjE3NTMxNzUxMzcsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.saPKjryn2mlrsHM03xbB3Q04iNul6ORmHzLfUuDh8Fxx4uxmzKHWs1gdOgfXs55KSetGkP2zQD8pTEIFkwqDkK7aIH-N6hEGzBq8j7MZ34nNZh5hjlZK3j8ReSN6T_U-6gL8yW5SzbhAVj7FZXdt7BqFRBJYamL6de8hjbcRjWSXn2Dh0-BeUTATWU2ryCp4oU2W9XFfBHfPngctPKmiF5ovG7bYPNVevD43e8ZRQFnuMoaB4C56romxZZKJ6ohoSQEOB9ccTX331xNhhC9oC2BjUql8AWooJgFG69hu7kp7Y4B5UWF20LcYKrV-_eMth0hr4LWKFDnH0CrDYhnUDA"
    val authCode = "c55d518ccd0bf4aa981d808ca54e96b5c.0.srtsx.zuuGCQtAdE8S0qqkR6Aotw"

    @Test
    fun testAppleJwtDecode() {
        val decoder = OpenIdJwtDecoder.apple()
        val token = decoder.decode(appleIdToken, authCode, ignoreExpiration = true)

        val appleToken =  token.toAppleIdToken()
        assertTrue(appleToken.emailVerified)
        assert(appleToken.email.isNotBlank())
    }
}