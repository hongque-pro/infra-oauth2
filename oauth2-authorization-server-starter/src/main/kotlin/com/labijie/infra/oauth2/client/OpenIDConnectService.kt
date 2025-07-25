package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.client.OpenIdJwtDecoder.Companion.fromUri
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.configuration.OAuth2ClientOidcLoginProperties
import com.labijie.infra.oauth2.client.converter.AppleOidcUserInfoConverter
import com.labijie.infra.oauth2.client.converter.GoogleOidcUserInfoConverter
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientProviderException
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientTokenException
import com.labijie.infra.utils.ifNullOrBlank
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.web.client.RestClient
import java.lang.IllegalStateException
import java.net.URI

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
class OpenIDConnectService(
    configuredProviders: Map<String, OAuth2ClientProperties.Provider>,
    infraOAuth2ClientProperties: InfraOAuth2ClientProperties,
    restClientBuilder: RestClient.Builder? = null,
) : IOpenIDConnectService {
    private val restClient: RestClient = restClientBuilder?.build() ?: RestClient.builder().build()

    val oauth2ClientProviders: Map<String, OAuth2ClientProperties.Provider>

    val supportDecoders: MutableMap<String, OpenIdJwtDecoder> = mutableMapOf()
    val userConverters: MutableMap<String, IOidcLoginUserInfoConverter> = mutableMapOf()
    val oidcLoginProperties: MutableMap<String, OAuth2ClientOidcLoginProperties> = mutableMapOf()

    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(InfraOAuth2ClientProperties::class.java)
        }
    }


    init {

        val providers = configuredProviders.map {
            it.key.lowercase() to it.value
        }.toMap().toMutableMap()

        CommonOAuth2Provider.entries.forEach {
            val name = it.name.lowercase()

            if (!providers.contains(name)) {
                try {
                    val client = it.getBuilder(it.name.lowercase())
                        .clientId("dummy")
                        .apply {
                            if(it.name == CommonOAuth2Provider.OKTA.name){
                                authorizationUri("https://dummpy.okta/authorize")
                                tokenUri("https://dummpy.okta/authorize")
                            }
                        }
                        .build()
                    val provider = OAuth2ClientProperties.Provider().apply {
                        this.issuerUri = client.providerDetails.issuerUri
                        this.jwkSetUri = client.providerDetails.jwkSetUri
                        this.tokenUri = client.providerDetails.tokenUri
                        this.userInfoUri = client.providerDetails.userInfoEndpoint.uri
                        this.authorizationUri = client.providerDetails.authorizationUri
                        this.userInfoAuthenticationMethod =
                            client.providerDetails.userInfoEndpoint.authenticationMethod.value
                        this.userNameAttribute = client.providerDetails.userInfoEndpoint.userNameAttributeName
                    }
                    providers.put(name, provider)
                }
                catch (ex: IllegalArgumentException) {
                    logger.error("Failed to build oauth2 provider: $name}", ex)
                }
            }
        }

        oauth2ClientProviders = providers

        val maps = mutableMapOf<String, OpenIdJwtDecoder>()


        for ((name, properties) in infraOAuth2ClientProperties.oidcLogin) {
            if (!maps.contains(name)) {
                val provider = providers.firstNotNullOfOrNull {
                    if (it.key.equals(name, ignoreCase = true)) {
                        it.value
                    } else null
                }

                provider?.let {
                    provider->
                    properties.jwkSetUri = properties.jwkSetUri.ifNullOrBlank { provider.jwkSetUri.orEmpty() }
                    properties.issuerUri = properties.issuerUri.ifNullOrBlank { provider.issuerUri.orEmpty() }
                    properties.userIdAttribute = properties.userIdAttribute.ifNullOrBlank { provider.userNameAttribute.orEmpty() }
                }

                if (properties.userIdAttribute.isBlank()) {
                    throw IllegalStateException("OAuth2 oidc login provider (${name}) configured, but it has empty user id attribute name.")
                    continue
                }

                if (properties.jwkSetUri.isBlank()) {
                    throw IllegalStateException("OAuth2 oidc login provider (${name}) configured, but it has no jwk set uri.")
                    continue
                }

                if (properties.issuerUri.isBlank()) {
                    throw IllegalStateException("OAuth2 oidc login provider (${name}) but is has no issuer uri.")
                    continue
                }

                val audSet = properties.audienceSet.split(",").map { it.trim() }.toSet()

                if (audSet.isEmpty()) {
                    logger.warn("OAuth2 oidc login provider has empty audience set, lack of aud set validation can cause security issues.")
                }

                maps[name.lowercase()] = fromUri(
                    name,
                    URI.create(properties.jwkSetUri),
                    properties.issuerUri,
                    audSet,
                    restClient
                )

                oidcLoginProperties.putIfAbsent(name.lowercase(), properties)
            }
        }

        userConverters.putIfAbsent(OAuth2ClientProviderNames.APPLE.lowercase(), AppleOidcUserInfoConverter)
        userConverters.putIfAbsent(OAuth2ClientProviderNames.GOOGLE.lowercase(), GoogleOidcUserInfoConverter)

        supportDecoders.putAll(maps)
    }

    override fun hasProvider(provider: String): Boolean {
        return supportDecoders.contains(provider.lowercase())
    }

    override fun allProviders(): Set<String> {
        return supportDecoders.keys
    }

    override fun addProvider(provider: IOpenIDConnectProvider) {
        val name = provider.providerName.lowercase()
        if(supportDecoders.contains(name)) {
            IllegalArgumentException("Oidc provider '${provider.providerName}' is already registered.")
        }
        supportDecoders.putIfAbsent(name, provider.decoder)
        userConverters.putIfAbsent(name, provider.converter)
    }

    override fun decodeToken(
        provider: String,
        jwt: String,
        authorizationCode: String?,
        nonce: String?,
        ignoreExpiration: Boolean,
    ): OAuth2LoginUser {
        val decoder = supportDecoders[provider.lowercase()] ?: throw InvalidOAuth2ClientProviderException(provider)
        val properties = oidcLoginProperties[provider.lowercase()] ?: throw InvalidOAuth2ClientProviderException(provider)

        val token = decoder.decode(jwt, authorizationCode, nonce, ignoreExpiration)
        val id = token.jwtClaimsSet.getStringClaim(properties.userIdAttribute)
        val clientId = token.jwtClaimsSet.audience.firstOrNull()

        if(id.isNullOrBlank()) {
            throw InvalidOAuth2ClientTokenException(provider, "User id attribute is null in id token (attribute: ${properties.userIdAttribute}, provider: $provider)")
        }

        val user = OAuth2LoginUser(provider.lowercase(),id, token, if(clientId.isNullOrBlank()) null else clientId)
        userConverters[provider.lowercase()]?.let {
            converter ->
            val userInfo = converter.convertFromToken(token)
            user.setInfo(userInfo)
        }

        return user
    }
}