package com.labijie.infra.oauth2.client

import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.AuthenticationMethod

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
class DefaultOAuth2ClientProviderService(
    oauth2ClientProperties: OAuth2ClientProperties? = null
) : IOAuth2ClientProviderService {

    val providers: MutableMap<String, OAuth2ClientProvider> = mutableMapOf()

    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(DefaultOAuth2ClientProviderService::class.java)
        }

        private val defaultScopeMaps: Map<String, Set<String>> = mapOf(
            OAuth2ClientProviderNames.APPLE to InfraOAuth2CommonsProviders.Apple.scopes,
            OAuth2ClientProviderNames.DISCORD to InfraOAuth2CommonsProviders.Discord.scopes,
        )
    }

    init {
        oauth2ClientProperties?.provider?.forEach { (key, value) ->
            val scopes = defaultScopeMaps[key.lowercase()]
            providers.putIfAbsent(
                key.lowercase(), OAuth2ClientProvider(
                    key.lowercase(),
                    issuerUri = value.issuerUri,
                    jwkSetUri = value.jwkSetUri,
                    tokenUri = value.tokenUri,
                    userInfoUri = value.userInfoUri,
                    authorizationUri = value.authorizationUri,
                    userInfoAuthenticationMethod = value.userInfoAuthenticationMethod?.let { AuthenticationMethod(it) },
                    userNameAttribute = value.userNameAttribute,
                    scopes = scopes ?: emptySet()
                )
            )
        }

        CommonOAuth2Provider.entries.forEach {
            val name = it.name.lowercase()

            if (!providers.contains(name)) {
                try {
                    val client = it.getBuilder(it.name.lowercase())
                        .clientId("dummy")
                        .apply {
                            if (it.name == CommonOAuth2Provider.OKTA.name) {
                                authorizationUri("https://dummpy.okta/authorize")
                                tokenUri("https://dummpy.okta/authorize")
                            }
                        }
                        .build()
                    val provider = OAuth2ClientProvider(
                        name,
                        issuerUri = client.providerDetails.issuerUri,
                        jwkSetUri = client.providerDetails.jwkSetUri,
                        tokenUri = client.providerDetails.tokenUri,
                        userInfoUri = client.providerDetails.userInfoEndpoint.uri,
                        authorizationUri = client.providerDetails.authorizationUri,
                        userInfoAuthenticationMethod = client.providerDetails.userInfoEndpoint.authenticationMethod,
                        userNameAttribute = client.providerDetails.userInfoEndpoint.userNameAttributeName,
                        scopes = client.scopes
                    )
                    providers.put(name, provider)
                } catch (ex: IllegalArgumentException) {
                    logger.error("Failed to build oauth2 provider: $name}", ex)
                }
            }
        }

        providers.putIfAbsent(OAuth2ClientProviderNames.APPLE, InfraOAuth2CommonsProviders.Apple)
        providers.putIfAbsent(OAuth2ClientProviderNames.DISCORD, InfraOAuth2CommonsProviders.Discord)
        providers.putIfAbsent(OAuth2ClientProviderNames.MICROSOFT, InfraOAuth2CommonsProviders.Microsoft)

    }

    override fun findByName(providerName: String): OAuth2ClientProvider? {
        return providers[providerName.lowercase()]
    }

    override fun getAllProviders(): Collection<OAuth2ClientProvider> {
        return providers.values
    }

    override fun findFromClient(client: ClientRegistration): OAuth2ClientProvider? {
        val currentAuthUri = client.providerDetails.authorizationUri
        val currentTokenUri = client.providerDetails.tokenUri

        val provider = providers.firstNotNullOfOrNull { (name, provider) ->

            if(name.equals(client.registrationId, ignoreCase = true)) {
                provider
            }else {
                val matched = provider.tokenUri?.let { currentTokenUri.equals(it, ignoreCase = true) } == true &&
                        provider.authorizationUri?.let { currentAuthUri.equals(it, ignoreCase = true) } == true
                if (matched) provider else null
            }
        }
        return provider
    }
}