/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.oauth2.core.OAuth2Error


interface IOAuthErrorWriter {
    fun writeErrorResponse(request: HttpServletRequest, response: HttpServletResponse, error: OAuth2Error, details: Map<String, Any>? = null)
}