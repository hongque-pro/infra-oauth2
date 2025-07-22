package com.labijie.infra.oauth2.client

import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
class DelegatingOAuth2UserService : OAuth2UserService<OAuth2UserRequest, OAuth2User>, ApplicationContextAware {

    private val defaultService = DefaultOAuth2UserService()
    private lateinit var applicationContext: ApplicationContext

    private val services by lazy {
        applicationContext.getBeanProvider(ICustomOAuth2UserService::class.java).orderedStream().toList()
    }


    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User? {
        return services.find { it.isSupported(userRequest.clientRegistration) }?.loadUser(userRequest) ?: defaultService.loadUser(userRequest)
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }
}