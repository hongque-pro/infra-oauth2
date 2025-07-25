package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.client.IOidcLoginHandler
import com.labijie.infra.oauth2.client.IOpenIDConnectService
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientProviderException
import jakarta.validation.Valid
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.*

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
@Suppress("SpringJavaInjectionPointsAutowiringInspection")
@RestController
@RequestMapping("/oauth2/connect")
@Validated
class OAuth2ClientLoginController(
    private val registeredClientRepository: RegisteredClientRepository? = null,
    private val oauth2ClientProperties: InfraOAuth2ClientProperties,
    private val oidcLoginHandler: IOidcLoginHandler?,
    private val openIdTokenService: IOpenIDConnectService,
) {

    @GetMapping("/oidc")
    fun oidcClients(): OidcClientsResponse {
        val providers = openIdTokenService.allProviders()

        return OidcClientsResponse(oidcLoginHandler != null && oauth2ClientProperties.oidcLoginEnabled, providers)
    }

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

    @GetMapping("/standard")
    fun webClients(): OAuth2ClientsResponse {
        return OAuth2ClientsResponse(registeredClientRepository != null, clients)
    }

    @PostMapping("/oidc-login/{provider}")
    fun oidcLogin(
        @PathVariable("provider") provider: String,
        @RequestBody(required = true) @Valid request: OidcLoginRequest,
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

        val accessToken = oidcLoginHandler.handle(user, request)

        return accessToken
    }
}