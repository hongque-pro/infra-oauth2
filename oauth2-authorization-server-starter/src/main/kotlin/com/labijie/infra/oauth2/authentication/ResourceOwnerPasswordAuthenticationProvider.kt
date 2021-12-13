package com.labijie.infra.oauth2.authentication

import com.labijie.infra.oauth2.TwoFactorSignInHelper
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken


class ResourceOwnerPasswordAuthenticationProvider(
    private val twoFactorSignInHelper: TwoFactorSignInHelper
) : AuthenticationProvider {


    companion object {
        private val LOGGER = LoggerFactory.getLogger(ResourceOwnerPasswordAuthenticationProvider::class.java)
    }


    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val resourceOwnerPasswordAuthentication = authentication as ResourceOwnerPasswordAuthenticationToken
        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(resourceOwnerPasswordAuthentication)
        val registeredClient = clientPrincipal.registeredClient
        if (!registeredClient!!.authorizationGrantTypes.contains(AuthorizationGrantType.PASSWORD)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }
        val additionalParameters: Map<String, Any> = resourceOwnerPasswordAuthentication.additionalParameters
        val username = additionalParameters[OAuth2ParameterNames.USERNAME] as? String
        val password = additionalParameters[OAuth2ParameterNames.PASSWORD] as? String

        if (username.isNullOrBlank() || password.isNullOrBlank()) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN)
        }

        return twoFactorSignInHelper.signIn(registeredClient, username, password, false, resourceOwnerPasswordAuthentication.scopes)
    }



    override fun supports(authentication: Class<*>): Boolean {
        val supports: Boolean =
            ResourceOwnerPasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
        LOGGER.debug("supports authentication=$authentication returning $supports")
        return supports
    }

    private fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
        var clientPrincipal: OAuth2ClientAuthenticationToken? = null
        if (OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication.principal::class.java)) {
            clientPrincipal = authentication.principal as? OAuth2ClientAuthenticationToken
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
            return clientPrincipal
        }
        throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
    }



}