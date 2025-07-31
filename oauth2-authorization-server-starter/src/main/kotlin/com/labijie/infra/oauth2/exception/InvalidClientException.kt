package com.labijie.infra.oauth2.exception

import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/31
 *
 */
class InvalidClientException(parameterName: String = OAuth2ParameterNames.CLIENT_ID) :
    OAuth2AuthenticationException(
        OAuth2Error(
            OAuth2ErrorCodes.INVALID_CLIENT,
            "Client authentication failed: $parameterName",
            "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1"
        )
    ) {
}