package com.labijie.infra.oauth2.resource.oauth2

import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
interface ICustomOAuth2UserService : OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    fun isSupported(client: ClientRegistration): Boolean
}