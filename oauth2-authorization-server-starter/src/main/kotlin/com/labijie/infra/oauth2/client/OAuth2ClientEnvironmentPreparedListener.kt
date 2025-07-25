package com.labijie.infra.oauth2.client

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent
import org.springframework.context.ApplicationListener
import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.core.env.MapPropertySource
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import java.util.*

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
class OAuth2ClientEnvironmentPreparedListener : ApplicationListener<ApplicationEnvironmentPreparedEvent> {


    override fun onApplicationEvent(p0: ApplicationEnvironmentPreparedEvent) {
        val env = p0.environment
        val defaults = oauthProviderProperties()
        env.propertySources.addLast(defaults)
    }

    private fun oauthProviderProperties(): MapPropertySource {
        LocaleContextHolder.setDefaultLocale(Locale.getDefault())
        val configMap = mutableMapOf<String, Any>()

        configMap.addOAuth2ClientProvider(OAuth2ClientProviderNames.APPLE, InfraOAuth2CommonsProviders.APPLE)
        configMap.addOAuth2ClientProvider(OAuth2ClientProviderNames.DISCORD, InfraOAuth2CommonsProviders.DISCORD)

        return MapPropertySource("spring.security.oauth2.client.provider", configMap)

    }

    private fun MutableMap<String, Any>.addOAuth2ClientProvider(name: String, provider: OAuth2ClientProperties.Provider) {
        val basePath = "spring.security.oauth2.client.provider.${name}"

        if(!provider.authorizationUri.isNullOrBlank()) {
            this.putIfAbsent("$basePath.authorization-uri", provider.authorizationUri)
        }
        if(!provider.tokenUri.isNullOrBlank()) {
            this.putIfAbsent("$basePath.token-uri", provider.tokenUri)
        }
        if(!provider.userInfoUri.isNullOrBlank()) {
            this.putIfAbsent("$basePath.user-info-uri", provider.userInfoUri)
        }
        if(!provider.jwkSetUri.isNullOrBlank()) {
            this.putIfAbsent("$basePath.jwk-set-uri", provider.jwkSetUri)
        }
        if (!provider.userNameAttribute.isNullOrBlank()) {
            this.putIfAbsent("$basePath.user-name-attribute", provider.userNameAttribute)
        }
        if (!provider.userNameAttribute.isNullOrBlank()) {
            this.putIfAbsent("$basePath.issuer-uri", provider.issuerUri)
        }
    }
}