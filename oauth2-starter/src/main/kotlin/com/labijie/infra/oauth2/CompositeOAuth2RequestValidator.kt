package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.OAuth2RequestValidator
import org.springframework.security.oauth2.provider.TokenRequest
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator

class CompositeOAuth2RequestValidator(private val serverProperties: OAuth2ServerProperties) : OAuth2RequestValidator {
    private val validator: DefaultOAuth2RequestValidator = DefaultOAuth2RequestValidator()

    override fun validateScope(authorizationRequest: AuthorizationRequest?, client: ClientDetails?) {
        if (serverProperties.scopeValidationEnabled) {
            validator.validateScope(authorizationRequest, client)
        }
    }

    override fun validateScope(tokenRequest: TokenRequest?, client: ClientDetails?) {
        if (serverProperties.scopeValidationEnabled) {
            validator.validateScope(tokenRequest, client)
        }
    }
}