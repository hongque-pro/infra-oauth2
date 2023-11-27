package com.labijie.infra.oauth2.authentication

import com.labijie.infra.oauth2.OAuth2Utils
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter
import org.springframework.util.MultiValueMap

/**
 * @author Anders Xiao
 * @date 2023-11-27
 */
class ResourceOwnerClientAuthenticationConverter : AuthenticationConverter {
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


        val clientPrincipal = basicAuthenticationConverter.convert(request)

        val additionalParameters: Map<String, Any> = parameters.entries
            .filter { e ->
                !e.key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                        !e.key.equals(OAuth2ParameterNames.SCOPE)
            }.associate {
                it.key to it.value.first()
            }
        val clientId = clientPrincipal.principal.toString()
        return OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientPrincipal.credentials, additionalParameters)
    }
}