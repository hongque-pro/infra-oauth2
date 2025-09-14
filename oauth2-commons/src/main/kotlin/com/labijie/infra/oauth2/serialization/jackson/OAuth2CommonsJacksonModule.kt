/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.labijie.infra.oauth2.AccessToken
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType


class OAuth2CommonsJacksonModule private constructor() : SimpleModule("infra.oauth2.commons") {
    init {
        this.addSerializer(AccessToken::class.java, AccessTokenSerializer())
        this.addDeserializer(AccessToken::class.java, AccessTokenDeserializer())

        this.addSerializer(OAuth2AuthorizationResponseType::class.java, OAuth2AuthorizationResponseTypeSerializer())
        this.addDeserializer(OAuth2AuthorizationResponseType::class.java, OAuth2AuthorizationResponseTypeDeserializer())

        this.addSerializer(AuthorizationGrantType::class.java, AuthorizationGrantTypeSerializer())
        this.addDeserializer(AuthorizationGrantType::class.java, AuthorizationGrantTypeDeserializer())

        this.addSerializer(OAuth2AuthorizationRequest::class.java, OAuth2AuthorizationRequestSerializer())
        this.addDeserializer(OAuth2AuthorizationRequest::class.java, OAuth2AuthorizationRequestDeserializer())

        this.addSerializer(AuthenticationMethod::class.java, AuthenticationMethodSerializer())
        this.addDeserializer(AuthenticationMethod::class.java, AuthenticationMethodDeserializer())
    }

    companion object {
        val INSTANCE by lazy { OAuth2CommonsJacksonModule() }
    }
}