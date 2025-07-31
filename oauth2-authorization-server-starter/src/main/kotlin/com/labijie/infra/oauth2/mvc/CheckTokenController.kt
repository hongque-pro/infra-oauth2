package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.IOAuth2ServerJwtCodec
import com.labijie.infra.oauth2.OAuth2Constants
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.web.bind.annotation.*
import java.time.Instant

@RestController
class CheckTokenController(
    private val jwtCodec: IOAuth2ServerJwtCodec
) {
    @RequestMapping(OAuth2Constants.ENDPOINT_CHECK_TOKEN, method = [RequestMethod.GET, RequestMethod.POST])
    @ResponseBody
    fun check(@RequestParam("token", required = true) token: String): CheckTokenResult {
        return try {
            val jwt = jwtCodec.decode(token)
            val active = (jwt.expiresAt?.epochSecond ?: 0) > Instant.now().epochSecond
            CheckTokenResult(active)
        }catch (_: JwtException){
            CheckTokenResult(false)
        }
    }

    @RequestMapping("/aa/{od}")
    fun t(
        @PathVariable("od") od: String,
    ): String {
        return ""
    }
}

data class CheckTokenResult(val active: Boolean)