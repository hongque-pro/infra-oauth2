package com.labijie.infra.oauth2.client

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
interface IOAuth2UserInfoLoader {
    fun load(provider: String, claims: ClaimsSet): StandardOidcUser
    fun load(provider: String, attributes: Map<String, Any>): StandardOidcUser
    fun load(provider: String, user: OAuth2User): StandardOidcUser
    fun load(client: ClientRegistration, user: OAuth2User) : StandardOidcUser
}