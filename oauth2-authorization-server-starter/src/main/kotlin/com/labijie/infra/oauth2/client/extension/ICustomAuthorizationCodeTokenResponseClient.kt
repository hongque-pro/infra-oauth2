package com.labijie.infra.oauth2.client.extension

import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
interface ICustomAuthorizationCodeTokenResponseClient :
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    fun isSupported(client: ClientRegistration): Boolean
}