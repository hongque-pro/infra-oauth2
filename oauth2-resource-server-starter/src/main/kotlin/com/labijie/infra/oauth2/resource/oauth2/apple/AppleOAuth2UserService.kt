package com.labijie.infra.oauth2.resource.oauth2.apple

import com.labijie.infra.oauth2.resource.oauth2.ICustomOAuth2UserService
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
class AppleOAuth2UserService: ICustomOAuth2UserService {
    override fun isSupported(client: ClientRegistration): Boolean {
        return client.registrationId.lowercase() == "apple"
    }

    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        val idTokenValue = userRequest.additionalParameters["id_token"] as? String
            ?: throw IllegalStateException("Missing id_token in Apple OAuth response")

        val jwt = SignedJWT.parse(idTokenValue)
        val claims = jwt.jwtClaimsSet

        val sub = claims.subject
        val email = claims.getStringClaim("email")
        val emailVerified = claims.getStringClaim("email_verified")

        val attributes = mapOf(
            "sub" to sub,
            "email" to email,
            "email_verified" to emailVerified
        )

        return DefaultOAuth2User(
            listOf(SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub" // 标识字段，必须与 registration.userNameAttributeName 一致
        )
    }
}