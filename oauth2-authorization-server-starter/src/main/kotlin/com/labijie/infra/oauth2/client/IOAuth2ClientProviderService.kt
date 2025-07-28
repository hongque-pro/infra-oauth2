package com.labijie.infra.oauth2.client

import org.springframework.security.oauth2.client.registration.ClientRegistration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
interface IOAuth2ClientProviderService {

    fun getAllProviders(): Collection<OAuth2ClientProvider>
    fun findByName(providerName: String): OAuth2ClientProvider?

    fun findFromClient(client: ClientRegistration): OAuth2ClientProvider?
}