package com.labijie.infra.oauth2.client

import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.StandardOidcUser.Companion.setInfo
import com.labijie.infra.oauth2.client.converter.AppleOidcUserConverter
import com.labijie.infra.oauth2.client.converter.DiscordOidcUserConverter
import com.labijie.infra.oauth2.client.converter.GithubOidcUserConverter
import com.labijie.infra.oauth2.client.converter.StandardOidcUserInfoConverter
import com.labijie.infra.oauth2.client.exception.InvalidOAuth2ClientProviderException
import com.labijie.infra.oauth2.client.exception.InvalidOauth2ClientTokenResponseException
import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet
import net.minidev.json.JSONObject
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
class DefaultOAuth2UserInfoLoader(
    private val providerService: IOAuth2ClientProviderService,
    converters: Collection<IOidcUserConverter> = emptySet<IOidcUserConverter>()
) : IOAuth2UserInfoLoader {

    private val converterMap: MutableMap<String, IOidcUserConverter> = mutableMapOf()

    init {
        converters.forEach {
            converterMap.putIfAbsent(it.getProvider().lowercase(), it)
        }
        converterMap.putIfAbsent(OAuth2ClientProviderNames.APPLE.lowercase(), AppleOidcUserConverter)
        converterMap.putIfAbsent(OAuth2ClientProviderNames.DISCORD.lowercase(), DiscordOidcUserConverter)
        converterMap.putIfAbsent(OAuth2ClientProviderNames.GITHUB.lowercase(), GithubOidcUserConverter)
    }

    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(DefaultOAuth2UserInfoLoader::class.java)
        }
    }

    private fun loadCore(provider: OAuth2ClientProvider, claimsSet: ClaimsSet, registrationId: String? = null): StandardOidcUser {
        val userid = claimsSet.getStringClaim(provider.userNameAttribute)

        if (userid.isNullOrBlank()) {
            val errorMessage = "Unable to got user id from claim '${provider.userNameAttribute}' (provider: ${provider.name})"
            logger.error("Failed to convert OAuth2User to StandardOidcUser.\n${errorMessage}")
            throw InvalidOauth2ClientTokenResponseException(errorMessage)
        }

        val converter = converterMap[provider.name.lowercase()] ?: StandardOidcUserInfoConverter


        val info = converter.convert(claimsSet)
        val user = StandardOidcUser(provider.name, userid, registrationId = registrationId)
        user.setInfo(info)
        return user
    }

    override fun load(provider: String, attributes: Map<String, Any>): StandardOidcUser {
        val p = providerService.findByName(provider) ?: throw InvalidOAuth2ClientProviderException(provider)
        val claimSet = ClaimsSet(JSONObject(attributes))
        return loadCore(p, claimSet)
    }


    override fun load(provider: String, user: OAuth2User): StandardOidcUser {
        val p = providerService.findByName(provider) ?: throw InvalidOAuth2ClientProviderException(provider)
        val claimSet = ClaimsSet(JSONObject(user.attributes))
        return loadCore(p, claimSet)
    }

    override fun load(client: ClientRegistration, user: OAuth2User): StandardOidcUser {
        val p = providerService.findFromClient(client) ?: throw InvalidOAuth2ClientProviderException("unknown")

        val claimSet = ClaimsSet(JSONObject(user.attributes))
        return loadCore(p, claimSet, client.clientId)
    }

    override fun load(provider: String, claims: ClaimsSet): StandardOidcUser {
        val p = providerService.findByName(provider) ?: throw InvalidOAuth2ClientProviderException(provider)

        return loadCore(p, claims)
    }
}