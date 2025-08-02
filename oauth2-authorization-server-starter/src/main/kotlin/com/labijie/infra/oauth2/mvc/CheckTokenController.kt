package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.IOAuth2ServerJwtCodec
import com.labijie.infra.oauth2.OAuth2Constants
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.jwt.JwtValidationException
import org.springframework.web.bind.annotation.*
import java.time.Instant

@RestController
class CheckTokenController(
    private val jwtCodec: IOAuth2ServerJwtCodec
) {
    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(CheckTokenController::class.java)
        }
    }

    @RequestMapping(OAuth2Constants.ENDPOINT_CHECK_TOKEN, method = [RequestMethod.GET, RequestMethod.POST])
    @ResponseBody
    fun check(@RequestParam("token", required = true) token: String): CheckTokenResult {
        return try {
            val jwt = jwtCodec.decode(token)
            val active = (jwt.expiresAt?.epochSecond ?: 0) > Instant.now().epochSecond
            CheckTokenResult(active)
        } catch (e: JwtValidationException) {
            logger.error("Decode jwt failed.", e)
            val result = CheckTokenResult(false)
           if(e.errors.isNotEmpty()) {
               result.errors = mutableMapOf()
               result.errors?.let {
                   e.errors.forEach {
                       error -> it.putIfAbsent(error.errorCode, error.description)
                   }
               }

           }
            result
        } catch (e: JwtException) {
            logger.error("Decode jwt failed.", e)
            CheckTokenResult(false)
        }
    }
}

data class CheckTokenResult(val active: Boolean) {
    var errors: MutableMap<String, String>? = null
}