package com.labijie.infra.oauth2.client.apple

import com.fasterxml.jackson.core.JacksonException
import com.fasterxml.jackson.databind.ObjectMapper
import com.labijie.infra.oauth2.client.ICustomOAuth2UserService
import com.labijie.infra.oauth2.client.OpenIdJwtDecoder
import com.labijie.infra.oauth2.client.exception.InvalidOauth2ClientTokenResponseException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.client.RestClient

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
class AppleOAuth2UserService(private val resetClientBuilder: RestClient.Builder): ICustomOAuth2UserService {


    override fun isSupported(client: ClientRegistration): Boolean {
        return client.registrationId.lowercase() == "apple"
    }

    private val resetClient by lazy {
        resetClientBuilder.build()
    }


    private val appleJwtDecoder: OpenIdJwtDecoder by lazy {
        OpenIdJwtDecoder.apple(resetClient)
    }

    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {

        val nameInfo = userRequest.additionalParameters["user"]?.let { user ->
            try {
                val json = ObjectMapper().readTree(user.toString())
                json["name"]?.let { nameNode ->
                    val mp = mutableMapOf<String, String>()
                    nameNode["firstName"]?.asText()?.let {
                        if(it.isNotBlank()) {
                            mp.putIfAbsent("firstName", it)
                        }
                    }

                    nameNode["lastName"]?.asText()?.let {
                        if(it.isNotBlank()) {
                            mp.putIfAbsent("firstName", it)
                        }
                    }
                    mp
                }
            } catch (_: JacksonException) {
                throw InvalidOauth2ClientTokenResponseException("Apple")
            }
        }

        val idTokenValue = userRequest.additionalParameters["id_token"] as? String
            ?: throw IllegalStateException("Missing id_token in Apple OAuth response")

        val jwt = appleJwtDecoder.decode(idTokenValue, userRequest.clientRegistration.clientId)

        val claims = jwt.jwtClaimsSet


        val attributes = HashMap<String, Any>(claims.claims)
        nameInfo?.let { attributes.putAll(it) }

        return DefaultOAuth2User(
            listOf(SimpleGrantedAuthority("ROLE_USER")),
            claims.claims,
            "sub" // 标识字段，必须与 registration.userNameAttributeName 一致
        )
    }
}