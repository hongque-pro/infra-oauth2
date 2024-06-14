/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2.serialization.jackson

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.ObjectMapper
import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2Constants
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames


class AccessTokenDeserializer : JsonDeserializer<AccessToken>() {
    override fun deserialize(parser: JsonParser, ctxt: DeserializationContext): AccessToken {
        val mapper = parser.codec as ObjectMapper
        val map = mapper.readValue<Map<String, Any>>(
            parser,
            mapper.typeFactory.constructMapType(Map::class.java, String::class.java, String::class.java)
        )
        return AccessToken().apply {
            this.accessToken = map[OAuth2ParameterNames.ACCESS_TOKEN].toString()
            this.expiresIn = map[OAuth2ParameterNames.EXPIRES_IN].toString().toLongOrNull() ?: 0
            this.tokenType = map[OAuth2ParameterNames.TOKEN_TYPE].toString()
            for (kv in map) {
                when (kv.key) {
                    OAuth2ParameterNames.ACCESS_TOKEN -> this.accessToken = kv.value.toString()
                    OAuth2ParameterNames.EXPIRES_IN -> this.expiresIn = kv.value.toString().toLongOrNull() ?: 0
                    OAuth2ParameterNames.TOKEN_TYPE -> this.tokenType = kv.value.toString()
                    OAuth2ParameterNames.SCOPE -> this.scope = kv.value.toString()
                    OAuth2Constants.CLAIM_TWO_FACTOR -> this.twoFactorGranted =
                        kv.value.toString().toBooleanStrictOrNull()

                    OAuth2Constants.CLAIM_USER_ID -> this.userId = kv.value.toString()
                    OAuth2Constants.CLAIM_USER_NAME -> this.username = kv.value.toString()
                    OAuth2ParameterNames.REFRESH_TOKEN -> this.refreshToken = kv.value.toString()
                    OAuth2Constants.CLAIM_AUTHORITIES -> {
                        val value = kv.value
                        if (value is Iterable<*>) {
                            this.authorities.addAll(value.map { it.toString() }.filter { it.isNotBlank() })
                        }
                    }
                    else->{
                        this.details.putIfAbsent(kv.key, kv.value)
                    }
                }
            }
        }
    }
}