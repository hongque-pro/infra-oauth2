package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.OAuth2ServerUtils.toAccessToken
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.client.*
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientProviderException
import com.labijie.infra.oauth2.client.provider.apple.AppleOneTimeIdentifier
import com.labijie.infra.oauth2.client.provider.apple.IAppleIdOneTimeStore
import com.labijie.infra.oauth2.filter.ClientRequired
import com.labijie.infra.oauth2.mvc.OidcLoginResult.Companion.getUser
import com.labijie.infra.oauth2.mvc.OidcLoginResult.Companion.isSuccess
import com.labijie.infra.oauth2.service.IOAuth2ServerOidcTokenService
import jakarta.validation.Valid
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.*
import java.time.Duration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
@RestController
@RequestMapping("/login")
@Validated
class OAuth2ClientLoginController(
    private val oauth2ServerOidcTokenService: IOAuth2ServerOidcTokenService,
    private val oauth2ClientProviderService: IOAuth2ClientProviderService,
    private val signInHelper: TwoFactorSignInHelper,
    private val registeredClientRepository: ClientRegistrationRepository?,
    private val oauth2ClientProperties: InfraOAuth2ClientProperties,
    @param:Autowired(required = false)
    private val oidcLoginHandler: IOidcLoginHandler?,
    private val openIdTokenService: IOpenIDConnectService,
) {

    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(OAuth2ClientLoginController::class.java)
        }
    }

    private val clients by lazy {
        val iterable = registeredClientRepository as? Iterable<*>

        val list = mutableListOf<OAuth2ClientProviderEntry>()
        iterable?.let {
            it.forEach { client ->
                if (client is ClientRegistration) {
                    val provider = oauth2ClientProviderService.findByName(client.registrationId)
                    val c = OAuth2ClientProviderEntry(
                        provider?.name ?: client.registrationId,
                        "${OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI}/${client.registrationId}",
                        default = provider != null,
                    )
                    list.add(c)
                }
            }
        }
        list
    }

    private val oidcLoginProviders by lazy {
        oauth2ClientProperties.oidcLogin.keys
    }

    @GetMapping("/providers")
    fun standardClients(): OAuth2ProvidersResponse {
        clients.filter {
            oauth2ClientProviderService.findByName(it.provider) != null
        }

        val oidc = OidcClientsInfo(oidcLoginHandler != null && oauth2ClientProperties.oidcLoginEnabled, oidcLoginProviders)

        val oauth2 = OAuth2ClientsInfo(registeredClientRepository != null, clients)

        return OAuth2ProvidersResponse(oauth2, oidc)
    }


    @ClientRequired
    @PostMapping("/oidc/{provider}")
    fun oidcLogin(
        @PathVariable("provider") provider: String,
        @RequestBody(required = true) @Valid request: OidcLoginRequest,
        client: RegisteredClient
    ): OAuth2ClientLoginResponse {

        if (oidcLoginHandler == null || !oauth2ClientProperties.oidcLoginEnabled) {
            throw InvalidOAuth2ClientProviderException(provider)
        }

        val user = openIdTokenService.decodeToken(provider, request.idToken, request.authorizationCode, request.nonce)

        if (user.username.isNullOrBlank()) {
            request.attributes?.get("username")?.let {
                user.username = user.username
            }
        }

        val result = oidcLoginHandler.handle(user, request)

        val response = if (result.isSuccess) {
            val auth = signInHelper.signIn(client, result.getUser(), false)
            OAuth2ClientLoginResponse.success(auth.toAccessToken())
        } else {
            val error = result.errorOrNull() ?: OAuth2Error(OAuth2ClientErrorCodes.INVALID_OIDC_TOKEN)
            val idToken = oauth2ServerOidcTokenService.encode(user, Duration.ofMinutes(15))
            OAuth2ClientLoginResponse.error(error.errorCode, idToken, error.description)
        }

        return response
    }
}