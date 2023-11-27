package com.labijie.infra.oauth2.authentication

import com.labijie.infra.oauth2.OAuth2Constants
import com.labijie.infra.oauth2.OAuth2Utils
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils


class ResourceOwnerPasswordAuthenticationConverter : AuthenticationConverter {

    companion object {
        val basicAuthenticationConverter = BasicAuthenticationConverter()
    }

    override fun convert(request: HttpServletRequest): Authentication? {

        // grant_type (REQUIRED)
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)
        if (grantType == null || grantType.compareTo(OAuth2Utils.PASSWORD_GRANT_TYPE.value, true) != 0) {
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


        val requestedScopes = if (StringUtils.hasText(scope)) {
            StringUtils.delimitedListToStringArray(scope, " ").toHashSet()
        } else {
            setOf()
        }

        // username (REQUIRED)
        val username = parameters.getFirst(OAuth2ParameterNames.USERNAME)
        if (username.isNullOrBlank() || parameters[OAuth2ParameterNames.USERNAME]?.size != 1) {
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

        val clientPrincipal = basicAuthenticationConverter.convert(request)

        val additionalParameters: Map<String, Any> = parameters.entries
            .filter { e ->
                !e.key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                        !e.key.equals(OAuth2ParameterNames.SCOPE)
            }.associate {
                it.key to it.value.first()
            }
        return ResourceOwnerPasswordAuthenticationToken(
            clientPrincipal.principal.toString(),
            clientPrincipal.credentials,
            requestedScopes,
            additionalParameters
        )
    }
}