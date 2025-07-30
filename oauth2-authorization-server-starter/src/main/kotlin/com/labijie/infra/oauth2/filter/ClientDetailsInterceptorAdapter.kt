package com.labijie.infra.oauth2.filter

import com.labijie.infra.oauth2.extractClientIdAndSecretFromHeader
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.HandlerInterceptor
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter
import java.time.Instant

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
class ClientDetailsInterceptorAdapter(private val registeredClientRepository: RegisteredClientRepository) :
    HandlerInterceptor {

    private val errorConverter = OAuth2ErrorHttpMessageConverter()

    companion object {
        private val error = OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Client authentication failed.", "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1")
    }

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        val method = handler as? HandlerMethod
        if (method != null) {
            val annotation = method.getMethodAnnotation(ClientRequired::class.java)
            if (annotation != null) {
                val (clientId, secret) = extractClientIdAndSecretFromHeader(request)
                if (clientId.isBlank()) {
                    writeError(response)
                    return false
                } else {
                    val clientDetail = registeredClientRepository.findByClientId(clientId)
                    if (clientDetail == null || ((clientDetail.clientSecretExpiresAt?.epochSecond
                            ?: Long.MAX_VALUE) < Instant.now().epochSecond) || !clientDetail.clientSecret.orEmpty()
                            .equals(secret, ignoreCase = false)
                    ) {
                        writeError(response)
                        return false
                    }
                    ClientDetailsHolder.setContext(clientDetail)
                }
            }
        }
        return true
    }

    private fun writeError(response: HttpServletResponse) {
        val serverResponse = ServletServerHttpResponse(response)
        serverResponse.setStatusCode(HttpStatus.UNAUTHORIZED)

        errorConverter.write(
            error, null, serverResponse
        )
    }

    override fun afterCompletion(
        request: HttpServletRequest,
        response: HttpServletResponse,
        handler: Any,
        ex: Exception?
    ) {
        ClientDetailsHolder.clearContext()
        super.afterCompletion(request, response, handler, ex)
    }
}