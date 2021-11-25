package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.Constants
import com.sun.deploy.xml.BadTokenException
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

@RestController
class CheckTokenController(
    private val jwtTokenDecoder: JwtDecoder
) {
    @PostMapping(Constants.DEFAULT_CHECK_TOKEN_ENDPOINT_PATH)
    @ResponseBody
    fun check(@RequestParam("token", required = true) token: String): CheckTokenResult {
        return try {
            val jwt = jwtTokenDecoder.decode(token)
            val active = (jwt.expiresAt?.epochSecond ?: 0) > Instant.now().epochSecond
            CheckTokenResult(active)
        }catch (_: JwtException){
            CheckTokenResult(false)
        }
    }
}

data class CheckTokenResult(val active: Boolean)