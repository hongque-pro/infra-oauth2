package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.IOAuth2ServerJwtCodec
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.web.bind.annotation.*
import java.time.Instant

@RestController
class CheckTokenController(
    private val jwtCodec: IOAuth2ServerJwtCodec
) {
    @RequestMapping(Constants.DEFAULT_CHECK_TOKEN_ENDPOINT_PATH)
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
}

data class CheckTokenResult(val active: Boolean)