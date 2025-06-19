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
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationContext
import org.springframework.http.ResponseEntity

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/23
 * @Description:
 */
class OAuth2ExceptionHandler private constructor() : AuthenticationFailureHandler, AccessDeniedHandler {
    companion object {

        @JvmStatic
        private var instance: OAuth2ExceptionHandler? = null

        @JvmStatic
        private val LOCK = Any()

        @JvmStatic
        fun getInstance(applicationContext: ApplicationContext?): OAuth2ExceptionHandler
        {
            if(instance == null) {
                synchronized(LOCK) {
                    if(instance == null) {
                        instance = OAuth2ExceptionHandler()
                    }
                }
            }
            val i = instance!!
            if(applicationContext != null && applicationContext != i.applicationContext) {
                i.applicationContext = applicationContext
            }
            return i
        }
    }

    private var applicationContext: ApplicationContext? = null

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException
    ) {
        writeError(request, response, exception, HttpStatus.UNAUTHORIZED)
    }

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException
    ) {
        //Access Denied
        writeError(request, response, accessDeniedException, HttpStatus.FORBIDDEN)
    }

    private val errorWriter by lazy {
        applicationContext?.getBeansOfType(IOAuthErrorWriter::class.java)?.values?.firstOrNull()
    }

    private fun writeError(request: HttpServletRequest,response: HttpServletResponse, ex: Exception, httpStatus: HttpStatus) {
        val (error, status) = when (ex) {
            is BadCredentialsException -> {
                Pair(
                    OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "User name or password is incorrect.", null),
                    httpStatus
                )
            }

            is OAuth2AuthenticationException -> {
                Pair(ex.error, httpStatus)
            }

            is InsufficientAuthenticationException -> {
                Pair(OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, ex.message, null), httpStatus)
            }

            is AuthenticationException -> {
                Pair(OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, ex.message, null), httpStatus)
            }

            is AccessDeniedException -> {
                Pair(
                    OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, ex.message.ifNullOrBlank { "Access denied." }, null),
                    httpStatus
                )
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

        val writer = errorWriter
        if(writer != null) {
            writer.writeErrorResponse(request, response, error)
            response.status = status.value()
            return
        }

        val errorMessage = mutableMapOf(
            "error" to error.errorCode,
            "error_description" to error.description.ifNullOrBlank { "Authenticate failed." }
        )
        if (!error.uri.isNullOrBlank()) {
            errorMessage["error_uri"] = error.uri
        }

        val message = JacksonHelper.defaultObjectMapper.writeValueAsString(errorMessage)
        response.status = status.value()
        response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
        response.characterEncoding = Charsets.UTF_8.name()
        response.writer.write(message)
    }


}