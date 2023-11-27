package com.labijie.infra.oauth2.authentication

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap


object OAuth2EndpointUtils {
    const val ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
    const val CLIENT_CREDENTIALS_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4"
    fun getParameters(request: HttpServletRequest): MultiValueMap<String, String> {
        val parameterMap = request.parameterMap
        val parameters: MultiValueMap<String, String> = LinkedMultiValueMap(parameterMap.size)
        parameterMap.forEach { (key: String?, values: Array<String?>) ->
            if (values.isNotEmpty()) {
                for (value in values) {
                    parameters.add(key, value)
                }
            }
        }
        return parameters
    }

    fun matchesPkceTokenRequest(request: HttpServletRequest): Boolean {
        return AuthorizationGrantType.AUTHORIZATION_CODE.value ==
                request.getParameter(OAuth2ParameterNames.GRANT_TYPE) && request.getParameter(OAuth2ParameterNames.CODE) != null && request.getParameter(
            PkceParameterNames.CODE_VERIFIER
        ) != null
    }

    fun makeError(errorCode: String?, parameterName: String, errorUri: String?): OAuth2AuthenticationException {
        val error = OAuth2Error(errorCode, "OAuth 2.0 Parameter: $parameterName", errorUri)
        return OAuth2AuthenticationException(error)
    }
}