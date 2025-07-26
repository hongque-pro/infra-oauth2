package com.labijie.infra.oauth2.client

import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
class DelegatingAuthorizationCodeTokenResponseClient :
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>, ApplicationContextAware {

    private lateinit var applicationContext: ApplicationContext

    private val clients by lazy {
        applicationContext.getBeanProvider(ICustomAuthorizationCodeTokenResponseClient::class.java).orderedStream()
            .toList()
    }

    override fun getTokenResponse(authorizationGrantRequest: OAuth2AuthorizationCodeGrantRequest): OAuth2AccessTokenResponse? {
        val client = clients.find { it.isSupported(authorizationGrantRequest.clientRegistration) }
        return client?.getTokenResponse(authorizationGrantRequest)
            ?: DefaultAuthorizationCodeTokenResponseClientClient.getTokenResponse(authorizationGrantRequest)
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }
}