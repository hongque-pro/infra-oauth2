package com.labijie.infra.oauth2.authentication

import com.labijie.infra.oauth2.NoopPasswordEncoder
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository


class ResourceOwnerPasswordAuthenticationProvider(
    private val twoFactorSignInHelper: TwoFactorSignInHelper,
    private val oauth2AuthorizationService: OAuth2AuthorizationService,
    private val registeredClientRepository : RegisteredClientRepository,

    ) : AuthenticationProvider {

    private val clientCredentialsAuthenticationProvider = ClientSecretAuthenticationProvider(registeredClientRepository, oauth2AuthorizationService)

    init {
        clientCredentialsAuthenticationProvider.setPasswordEncoder(NoopPasswordEncoder())
    }


    companion object {
        private val LOGGER = LoggerFactory.getLogger(ResourceOwnerPasswordAuthenticationProvider::class.java)
    }


    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {

        val resourceOwnerPasswordAuthentication = authentication as ResourceOwnerPasswordAuthenticationToken

//        if (!ClientAuthenticationMethod.NONE.equals(deviceClientAuthentication.getClientAuthenticationMethod())) {
//            return null;
//        }

        val clientId: String = resourceOwnerPasswordAuthentication.principal.toString()


        val registeredClient: RegisteredClient = registeredClientRepository.findByClientId(clientId) ?: throw OAuth2EndpointUtils.makeError(
            OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE,
            OAuth2ParameterNames.GRANT_TYPE,
            OAuth2EndpointUtils.CLIENT_CREDENTIALS_ERROR_URI
        )

        clientCredentialsAuthenticationProvider.authenticate(resourceOwnerPasswordAuthentication.toOAuth2ClientAuthenticationToken()) ?: throw OAuth2EndpointUtils.makeError(
            OAuth2ErrorCodes.INVALID_CLIENT,
            OAuth2ParameterNames.CLIENT_ID,
            OAuth2EndpointUtils.CLIENT_CREDENTIALS_ERROR_URI
        )



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
        LOGGER.debug("supports authentication=${authentication::class.java.simpleName} returning $supports")
        return supports
    }


}