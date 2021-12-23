package com.labijie.infra.oauth2

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.utils.ifNullOrBlank
import com.labijie.infra.utils.logger
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/23
 * @Description:
 */
class OAuth2ExceptionHandler private constructor() : AuthenticationFailureHandler, AccessDeniedHandler {
    companion object {

        @JvmStatic
        val INSTANCE : OAuth2ExceptionHandler by lazy {
            OAuth2ExceptionHandler()
        }
    }

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException
    ) {
        writeError(response, exception)
    }

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException
    ) {
        writeError(response, accessDeniedException)
    }

    private fun writeError(response: HttpServletResponse, ex: Exception) {
        val (error, status) = when (ex) {
            is BadCredentialsException -> {
                Pair(OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "User name or password is incorrect.", null), HttpStatus.UNAUTHORIZED)
            }
            is OAuth2AuthenticationException -> {
                Pair(ex.error, HttpStatus.UNAUTHORIZED)
            }
            is InsufficientAuthenticationException -> {
                Pair(OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, ex.message, null), HttpStatus.UNAUTHORIZED)
            }
            is AuthenticationException -> {
                Pair(OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, ex.message, null), HttpStatus.UNAUTHORIZED)
            }
            is AccessDeniedException -> {
                Pair(OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, ex.message.ifNullOrBlank { "Access denied." }, null), HttpStatus.UNAUTHORIZED)
            }
            else -> {
                logger.error("Unhandled error has occurred in AuthenticationFailureHandler", ex)
                val err = OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "Unhandled error has occurred when handle authentication failure.",
                    null
                )
                Pair(err, HttpStatus.INTERNAL_SERVER_ERROR)
            }
        }

        val errorMessage = mutableMapOf(
            "error" to error.errorCode,
            "error_description" to error.description.ifNullOrBlank { "Authenticate failed." }
        )
        if(!error.uri.isNullOrBlank()){
            errorMessage["error_uri"] = error.uri
        }

        val message = JacksonHelper.defaultObjectMapper.writeValueAsString(errorMessage)
        response.status = status.value()
        response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
        response.writer.write(message)
    }


}