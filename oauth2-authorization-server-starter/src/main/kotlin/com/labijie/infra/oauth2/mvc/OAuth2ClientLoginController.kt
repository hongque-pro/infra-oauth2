package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2ServerUtils.toAccessToken
import com.labijie.infra.oauth2.StandardOidcUser.Companion.getInfo
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.client.IOAuth2ClientProviderService
import com.labijie.infra.oauth2.client.IOidcLoginHandler
import com.labijie.infra.oauth2.client.IOpenIDConnectService
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientProviderException
import com.labijie.infra.oauth2.client.exception.OAuth2LoginException
import com.labijie.infra.oauth2.filter.ClientRequired
import com.labijie.infra.oauth2.mvc.OidcLoginResponse.Companion.getOrElse
import jakarta.validation.Valid
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.*

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
@RequestMapping("/login")
@Validated
class OAuth2ClientLoginController(
    private val oAuth2ClientProviderService: IOAuth2ClientProviderService,
    private val signInHelper: TwoFactorSignInHelper,
    private val registeredClientRepository: RegisteredClientRepository? = null,
    private val oauth2ClientProperties: InfraOAuth2ClientProperties,
    private val oidcLoginHandler: IOidcLoginHandler?,
    private val openIdTokenService: IOpenIDConnectService,
) {

    private val clients by lazy {
        val iterable = registeredClientRepository as? Iterable<*>

        val list = mutableListOf<OAuth2ClientProviderEntry>()
        iterable?.let {
            it.forEach { client ->
                if (client is ClientRegistration) {
                    val c = OAuth2ClientProviderEntry(
                        client.registrationId,
                        client.clientName,
                        "${OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI}/${client.registrationId}"
                    )
                    list.add(c)
                }
            }
        }
        list
    }

    @GetMapping("/providers/oauth2")
    fun standardClients(): OAuth2ClientsResponse {
        clients.filter {
            oAuth2ClientProviderService.findByName(it.provider) != null
        }
        return OAuth2ClientsResponse(registeredClientRepository != null, clients)
    }

    @GetMapping("/providers/id-token")
    fun oidcClients(): OidcClientsResponse {
        val providers = openIdTokenService.allProviders()

        return OidcClientsResponse(oidcLoginHandler != null && oauth2ClientProperties.oidcLoginEnabled, providers)
    }



    @ClientRequired
    @PostMapping("/id-token/{provider}")
    fun oidcLogin(
        @PathVariable("provider") provider: String,
        @RequestBody(required = true) @Valid request: OidcLoginRequest,
        client: RegisteredClient
    ): AccessToken {

        if(oidcLoginHandler == null || !oauth2ClientProperties.oidcLoginEnabled) {
            throw InvalidOAuth2ClientProviderException(provider)
        }

        val user = openIdTokenService.decodeToken(provider, request.idToken, request.authorizationCode, request.nonce)

        if(user.username.isNullOrBlank()) {
            request.attributes?.get("username")?.let {
                user.username = user.username
            }
        }

        val result = oidcLoginHandler.handle(user, request)

        val signedInUser = result.getOrElse {
            throw OAuth2LoginException(provider, it.error).apply {
                this.userInfo = user.getInfo()
            }
        }

        val auth = signInHelper.signIn(client, signedInUser, false)
        return auth.toAccessToken()
    }
}