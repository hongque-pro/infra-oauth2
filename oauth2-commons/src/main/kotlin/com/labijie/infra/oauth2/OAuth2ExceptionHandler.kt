package com.labijie.infra.oauth2

import com.labijie.infra.utils.ifNullOrBlank
import com.labijie.infra.utils.logger
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationContext
import org.springframework.http.HttpStatus
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.csrf.CsrfException

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/23
 * @Description:
 */
object OAuth2ExceptionHandler : AuthenticationFailureHandler, AccessDeniedHandler {

    private var applicationContext: ApplicationContext? = null

    fun setApplicationContext(applicationContext: ApplicationContext?) {
        this.applicationContext = applicationContext
    }

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException
    ) {
        writeError(response, exception, HttpStatus.UNAUTHORIZED, request)
    }

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException
    ) {
        writeError(response, accessDeniedException, HttpStatus.FORBIDDEN, request)
    }

    private val errorWriter by lazy {
        applicationContext?.getBeansOfType(IOAuthErrorWriter::class.java)?.values?.firstOrNull()
    }

    private data class NormalizedError(val error: OAuth2Error, val status: HttpStatus)

    fun writeError(response: HttpServletResponse, ex: Exception, httpStatus: HttpStatus, request: HttpServletRequest? = null) {

        val (error, status) = when (ex) {
            is BadCredentialsException -> {
                NormalizedError(
                    OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "User name or password is incorrect.", null),
                    httpStatus
                )
            }

            is CsrfException -> {
                NormalizedError(OAuth2Error(SecurityErrorCodes.INVALID_CSRF_TOKEN), httpStatus)
            }

            is OAuth2ClientAuthenticationException-> {
                NormalizedError(ex.error, httpStatus)
            }

            is OAuth2AuthenticationException -> {
                NormalizedError(ex.error, httpStatus)
            }

            is InsufficientAuthenticationException -> {
                NormalizedError(OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, ex.message, null), httpStatus)
            }

            is AuthenticationException -> {
                NormalizedError(OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, ex.message, null), httpStatus)
            }

            is AccessDeniedException -> {
                NormalizedError(
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
                NormalizedError(err, HttpStatus.INTERNAL_SERVER_ERROR)
            }
        }

        val writer = errorWriter
        if(writer != null) {
            writer.writeErrorResponse(request, response, error)
            response.status = status.value()
            return
        }


        response.writeOAuth2Error(error, status)
    }



    private val errorConverter = OAuth2ErrorHttpMessageConverter()


    private fun HttpServletResponse.writeOAuth2Error(error: OAuth2Error, status: HttpStatus) {
        val serverResponse = ServletServerHttpResponse(this)
        serverResponse.setStatusCode(status)

        errorConverter.write(
            error, null, serverResponse
        )
    }


}