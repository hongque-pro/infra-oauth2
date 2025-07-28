package com.labijie.infra.oauth2.serialization

import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import java.net.URI

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
internal class PlainOAuth2AuthorizationRequest {
    var authorizationGrantType: String? = null
    var authorizationUri: String? = null
    var clientId: String? = null
    var redirectUri: String? = null
    var scopes: MutableSet<String> = mutableSetOf()
    var state: String? = null
    var additionalParameters: MutableMap<String?, Any?>? = null
    var authorizationRequestUri: String? = null
    var attributes: MutableMap<String?, Any?>? = null

    companion object {
        fun OAuth2AuthorizationRequest.toPlain(): PlainOAuth2AuthorizationRequest {
            if (!this.grantType.equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                throw IllegalArgumentException("Invalid authorizationGrantType, only AUTHORIZATION_CODE request supported.")
            }

            return PlainOAuth2AuthorizationRequest().also { plain ->
                plain.authorizationUri = authorizationUri?.let { uri-> if(uri.isBlank()) uri else URI.create(this.authorizationUri).let {
                    URI(
                        it.scheme,
                        it.getAuthority(),
                        it.getPath(),
                        null,
                        it.getFragment()
                    ).toString()
                } }
                plain.clientId = clientId
                plain.redirectUri = redirectUri
                plain.state = state
                plain.additionalParameters = additionalParameters
                plain.authorizationRequestUri = authorizationRequestUri
                plain.attributes = attributes
                plain.authorizationGrantType = this.grantType?.value
                plain.scopes = this.scopes?.toMutableSet() ?: mutableSetOf()
            }
        }


        fun PlainOAuth2AuthorizationRequest.toOAuth2AuthorizationRequest(): OAuth2AuthorizationRequest {
            if (this.authorizationGrantType != AuthorizationGrantType.AUTHORIZATION_CODE.value) {
                throw IllegalArgumentException("Invalid authorizationGrantType, only AUTHORIZATION_CODE request supported.")
            }
            val builder = OAuth2AuthorizationRequest.authorizationCode()
            authorizationUri?.let { builder.authorizationUri(it) }
            clientId?.let { builder.clientId(it) }
            redirectUri?.let { builder.redirectUri(it) }
            state?.let { builder.state(it) }
            additionalParameters?.let { builder.additionalParameters(it) }
            authorizationRequestUri?.let { builder.authorizationRequestUri(it) }
            attributes?.let { builder.attributes(it) }
            scopes.let { builder.scopes(it) }
            return builder.build()
        }
    }
}