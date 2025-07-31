package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.OAuth2Utils.toClaimSet
import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.StandardOidcUser.Companion.getInfo
import com.labijie.infra.oauth2.StandardOidcUser.Companion.setInfo
import com.labijie.infra.oauth2.client.OpenIdJwtDecoder.Companion.fromUri
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.configuration.OAuth2ClientOidcLoginProperties
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientProviderException
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientTokenException
import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.labijie.infra.oauth2.client.extension.IOpenIDConnectProvider
import com.labijie.infra.utils.ifNullOrBlank
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.web.client.RestClient
import java.net.URI

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
class DefaultOpenIDConnectService(
    clientRepository: ClientRegistrationRepository?,
    private val userInfoLoader: IOAuth2UserInfoLoader,
    private val oauth2ClientProviderService: IOAuth2ClientProviderService,
    infraOAuth2ClientProperties: InfraOAuth2ClientProperties,
    restClientBuilder: RestClient.Builder? = null,
) : IOpenIDConnectService {

    //for unit test
    constructor(providerService: IOAuth2ClientProviderService, restClientBuilder: RestClient.Builder? = null) : this(
        null,
        DefaultOAuth2UserInfoLoader(providerService),
        providerService,
        InfraOAuth2ClientProperties(),
        restClientBuilder)

    private val restClient: RestClient = restClientBuilder?.build() ?: RestClient.builder().build()


    val supportDecoders: MutableMap<String, OpenIdJwtDecoder> = mutableMapOf()
    val converters: MutableMap<String, IOidcUserConverter> = mutableMapOf()
    val oidcLoginProperties: MutableMap<String, OAuth2ClientOidcLoginProperties> = mutableMapOf()

    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(InfraOAuth2ClientProperties::class.java)
        }
    }


    init {

        val maps = mutableMapOf<String, OpenIdJwtDecoder>()

        for ((name, properties) in infraOAuth2ClientProperties.oidcLogin) {
            if (!maps.contains(name)) {
                val provider = oauth2ClientProviderService.findByName(name)

                provider?.let { provider ->
                    properties.jwkSetUri = properties.jwkSetUri.ifNullOrBlank { provider.jwkSetUri.orEmpty() }
                    properties.issuerUri = properties.issuerUri.ifNullOrBlank { provider.issuerUri.orEmpty() }
                    properties.userIdAttribute =
                        properties.userIdAttribute.ifNullOrBlank { provider.userNameAttribute.orEmpty() }
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

                oidcLoginProperties.putIfAbsent(name.lowercase(), properties)
            }
        }


        val clients = (clientRepository as? Iterable<*>)?.mapNotNull {
            it as? ClientRegistration
        }?.groupBy { oauth2ClientProviderService.findFromClient(it)?.name ?: it.registrationId } ?: emptyMap()

        val providers = oauth2ClientProviderService.getAllProviders()
        for (provider in providers) {
            val providerName = provider.name.lowercase()
            val found = oidcLoginProperties[providerName]

            val jwkSetUri = found?.jwkSetUri.ifNullOrBlank { provider.jwkSetUri.orEmpty() }
            val issuerUri = found?.issuerUri ?: provider.issuerUri.orEmpty()

            if (jwkSetUri.isBlank()) {
                continue
            }

            val audSet = mutableSetOf<String>()
            found?.audienceSet?.split(",")?.map { it.trim() }?.let {
                audSet.addAll(it)
            }

            clients[providerName]?.let { clientList ->
                val clientIds = clientList.map { it.clientId }
                audSet.addAll(clientIds)
            }

            val decoder = fromUri(
                providerName,
                URI.create(jwkSetUri),
                issuerUri,
                audSet,
                restClient
            )
            supportDecoders.putIfAbsent(providerName, decoder)
        }
    }


    override fun hasProvider(provider: String): Boolean {
        return supportDecoders.contains(provider.lowercase())
    }

    override fun allProviders(): Set<String> {
        return supportDecoders.keys
    }

    override fun addProvider(provider: IOpenIDConnectProvider) {
        val name = provider.providerName.lowercase()
        if (supportDecoders.contains(name)) {
            IllegalArgumentException("Oidc provider '${provider.providerName}' is already registered.")
        }
        supportDecoders.putIfAbsent(name, provider.decoder)
        provider.converter?.let {
            converters.putIfAbsent(name, it)
        }
    }

    private fun getUserIdAttribute(provider: String): String? {
        val attribute = oidcLoginProperties[provider.lowercase()]?.userIdAttribute
        return attribute.ifNullOrBlank {
            oauth2ClientProviderService.findByName(provider)?.userNameAttribute ?: IdTokenClaimNames.SUB
        }
    }

    override fun decodeToken(
        provider: String,
        jwt: String,
        authorizationCode: String?,
        nonce: String?,
        ignoreExpiration: Boolean,
    ): StandardOidcUser {

        val idAttribute = getUserIdAttribute(provider)

        if (idAttribute.isNullOrBlank()) {
            throw InvalidOAuth2ClientTokenException(
                provider,
                "User id attribute is null in id token (provider: $provider)"
            )
        }

        val decoder = supportDecoders[provider.lowercase()] ?: throw InvalidOAuth2ClientProviderException(provider)

        val token = decoder.decode(jwt, authorizationCode, nonce, ignoreExpiration)
        val id = token.jwtClaimsSet.getStringClaim(idAttribute)
        val clientId = token.jwtClaimsSet.audience.firstOrNull()


        val user = StandardOidcUser(
            provider.lowercase(),
            id,
            token,
            registrationId = if (clientId.isNullOrBlank()) null else clientId
        )
        val converter = converters[provider.lowercase()]
        val claimSet = token.jwtClaimsSet.toClaimSet()

        val userInfo = converter?.convert(claimSet) ?: userInfoLoader.load(provider, claimSet).getInfo()

        user.setInfo(userInfo)

        return user
    }
}