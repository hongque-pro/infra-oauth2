package com.labijie.infra.oauth2.authentication

import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils
import javax.servlet.http.HttpServletRequest


class ResourceOwnerPasswordAuthenticationConverter : AuthenticationConverter {
    override fun convert(request: HttpServletRequest): Authentication? {

        // grant_type (REQUIRED)
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)
        if (AuthorizationGrantType.PASSWORD.value != grantType) {
            return null
        }
        val parameters: MultiValueMap<String, String> = OAuth2EndpointUtils.getParameters(request)

        // scope (OPTIONAL)
        val scope = parameters.getFirst(OAuth2ParameterNames.SCOPE)
        if (StringUtils.hasText(scope) &&
            parameters[OAuth2ParameterNames.SCOPE]?.size != 1
        ) {
            throw OAuth2EndpointUtils.makeError(
                OAuth2ErrorCodes.INVALID_REQUEST,
                OAuth2ParameterNames.SCOPE,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI
            )
        }

        var requestedScopes: Set<String>? = null
        if (StringUtils.hasText(scope)) {
            requestedScopes = StringUtils.delimitedListToStringArray(scope, " ").toSet()
        }

        // username (REQUIRED)
        val username = parameters.getFirst(OAuth2ParameterNames.USERNAME)
        if (!StringUtils.hasText(username) || parameters[OAuth2ParameterNames.USERNAME]?.size != 1) {
            throw OAuth2EndpointUtils.makeError(
                OAuth2ErrorCodes.INVALID_REQUEST,
                OAuth2ParameterNames.USERNAME,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI
            )
        }

        // password (REQUIRED)
        val password = parameters.getFirst(OAuth2ParameterNames.PASSWORD)
        if (!StringUtils.hasText(password) || parameters[OAuth2ParameterNames.PASSWORD]?.size != 1) {
            throw OAuth2EndpointUtils.makeError(
                OAuth2ErrorCodes.INVALID_REQUEST,
                OAuth2ParameterNames.PASSWORD,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI
            )
        }
        val clientPrincipal = SecurityContextHolder.getContext()?.authentication ?: throw OAuth2EndpointUtils.makeError(
            OAuth2ErrorCodes.INVALID_REQUEST,
            OAuth2ErrorCodes.INVALID_CLIENT,
            OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI
        )
        val additionalParameters: Map<String, Any> = parameters.entries
            .filter { e ->
                !e.key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                        !e.key.equals(OAuth2ParameterNames.SCOPE)
            }.associate {
                it.key to it.value.first()
            }
        return ResourceOwnerPasswordAuthenticationToken(
            AuthorizationGrantType.PASSWORD,
            clientPrincipal,
            requestedScopes,
            additionalParameters
        )
    }
}