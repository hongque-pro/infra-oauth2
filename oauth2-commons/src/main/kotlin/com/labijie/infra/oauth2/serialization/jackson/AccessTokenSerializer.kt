/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2Constants
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames


class AccessTokenSerializer : JsonSerializer<AccessToken>() {
    override fun serialize(value: AccessToken, gen: JsonGenerator, serializers: SerializerProvider) {

        gen.writeStartObject()
        serializers.defaultSerializeField(OAuth2ParameterNames.ACCESS_TOKEN, value.accessToken, gen)
        serializers.defaultSerializeField(OAuth2ParameterNames.EXPIRES_IN, value.expiresIn, gen)
        serializers.defaultSerializeField(OAuth2ParameterNames.TOKEN_TYPE, value.tokenType, gen)
        serializers.defaultSerializeField(OAuth2ParameterNames.SCOPE, value.scope, gen)
        serializers.defaultSerializeField(OAuth2Constants.CLAIM_TWO_FACTOR, value.twoFactorGranted, gen)
        serializers.defaultSerializeField(OAuth2Constants.CLAIM_USER_ID, value.userId, gen)
        serializers.defaultSerializeField(OAuth2Constants.CLAIM_USER_NAME, value.username, gen)
        serializers.defaultSerializeField(OAuth2ParameterNames.REFRESH_TOKEN, value.refreshToken, gen)
        serializers.defaultSerializeField(OAuth2Constants.CLAIM_AUTHORITIES, value.authorities, gen)

        value.details.forEach {
            serializers.defaultSerializeField(it.key, it.value, gen)
        }
        gen.writeEndObject()
    }
}