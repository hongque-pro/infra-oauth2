package com.labijie.infra.oauth2

import com.fasterxml.jackson.core.type.TypeReference
import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.OAuth2ServerUtils.md5Hex
import com.labijie.infra.oauth2.OAuth2ServerUtils.toInstant
import com.labijie.infra.oauth2.jackson.OAuth2JacksonModule
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import java.time.Instant
import kotlin.reflect.KClass
import kotlin.reflect.full.createInstance

class OAuth2AuthorizationSerializer(private val clientRepository: RegisteredClientRepository) {

    companion object {
        private val objectMapper = JacksonHelper.defaultObjectMapper.copy().apply {
            val classLoader = JdbcOAuth2AuthorizationService::class.java.classLoader
            val securityModules = SecurityJackson2Modules.getModules(classLoader)
            this.registerModules(securityModules)
            this.registerModule(OAuth2AuthorizationServerJackson2Module())
            this.registerModule(OAuth2JacksonModule())
        }
    }


    private fun writeMap(data: Map<String, Any>): String {
        return try {
            objectMapper.writeValueAsString(data)
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    private fun readMap(data: String): Map<String, Any> {
        if (data.isBlank()) {
            return mapOf()
        }
        return try {
            objectMapper.readValue(data, object : TypeReference<Map<String, Any>>() {})
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    private fun <T : AbstractOAuth2Token, O : TokenPlainObject> parseToken(
        token: OAuth2Authorization.Token<T>?,
        objectType: KClass<O>,
        customizer: ((t: OAuth2Authorization.Token<T>, o: O) -> Unit)? = null
    ): O? {

        val t = token?.token
        if (t != null && !t.tokenValue.isNullOrBlank()) {
            return objectType.createInstance().apply {
                this.tokenValue = t.tokenValue
                this.issuedAtEpochSecond = t.issuedAt?.epochSecond
                this.expiresAtEpochSecond = t.expiresAt?.epochSecond
                this.metadata = writeMap(token.metadata)
                customizer?.invoke(token, this)
            }
        }
        return null
    }

    fun readTokenId(authorization: OAuth2Authorization): String {
        val accessToken = authorization.getToken(OAuth2AccessToken::class.java)?.token?.tokenValue
        if(!accessToken.isNullOrBlank()){
            return accessToken.md5Hex()
        }

        val authorizationCode = authorization.getToken(OAuth2AuthorizationCode::class.java)?.token?.tokenValue
        if(!authorizationCode.isNullOrBlank()){
            return authorizationCode.md5Hex()
        }

        val oidcIdToken = authorization.getToken(OidcIdToken::class.java)?.token?.tokenValue
        if(!oidcIdToken.isNullOrBlank()){
            return oidcIdToken.md5Hex()
        }

        return authorization.id
    }

    fun serialize(authorization: OAuth2Authorization): AuthorizationPlainObject {
        val plainObject = AuthorizationPlainObject()

        plainObject.id = authorization.id
        plainObject.clientId = authorization.registeredClientId
        plainObject.principalName = authorization.principalName
        plainObject.grantType = authorization.authorizationGrantType.value

        val attributes: String = writeMap(authorization.attributes)
        plainObject.attributes = attributes

        val authorizationState = authorization.getAttribute<String>(OAuth2ParameterNames.STATE)
        if (!authorizationState.isNullOrBlank()) {
            plainObject.state = authorizationState
        }

        val authorizationCode = authorization.getToken(OAuth2AuthorizationCode::class.java)
        plainObject.authorizationCodeToken = parseToken(authorizationCode, TokenPlainObject::class)

        val accessToken = authorization.getToken(OAuth2AccessToken::class.java)
        plainObject.accessToken = parseToken(accessToken, AccessTokenPlainObject::class) { t, o ->
            o.tokenType = t.token.tokenType.value
            if (t.token.scopes.isNotEmpty()) {
                o.scopes = t.token.scopes.toTypedArray()
            }
        }

        val oidcIdToken = authorization.getToken(OidcIdToken::class.java)
        plainObject.oidcIdToken = parseToken(oidcIdToken, TokenPlainObject::class)


        val refreshToken = authorization.refreshToken
        plainObject.refreshToken = parseToken(refreshToken, TokenPlainObject::class)

        return plainObject
    }

    fun deserialize(plainObject: AuthorizationPlainObject): OAuth2Authorization {
        val registeredClient: RegisteredClient = clientRepository.findById(plainObject.clientId)
            ?: throw DataRetrievalFailureException(
                "The RegisteredClient with id '${plainObject.clientId.ifEmpty { "<empty>" }}' was not found in the RegisteredClientRepository."
            )

        val builder = OAuth2Authorization.withRegisteredClient(registeredClient)
        val attributes = readMap(plainObject.attributes)

        builder.id(plainObject.id)
            .principalName(plainObject.principalName)
            .authorizationGrantType(AuthorizationGrantType(plainObject.grantType))
            .attributes {
                it.putAll(attributes)
            }

        val state = plainObject.state
        if (!state.isNullOrBlank()) {
            builder.attribute(OAuth2ParameterNames.STATE, state)
        }

        val code = plainObject.authorizationCodeToken
        if (code != null) {
            val authorizationCodeMetadata = readMap(code.metadata)
            val authorizationCode = OAuth2AuthorizationCode(
                code.tokenValue,
                code.issuedAtEpochSecond.toInstant(),
                code.expiresAtEpochSecond.toInstant()
            )
            builder.token(
                authorizationCode
            ) { metadata ->
                metadata.putAll(
                    authorizationCodeMetadata
                )
            }
        }

        val accessToken = plainObject.accessToken
        if (accessToken != null) {
            val accessTokenMetadata = readMap(accessToken.metadata)
            var tokenType: OAuth2AccessToken.TokenType? = null
            if (OAuth2AccessToken.TokenType.BEARER.value.equals(accessToken.tokenType, ignoreCase = true)) {
                tokenType = OAuth2AccessToken.TokenType.BEARER
            }
            val t = OAuth2AccessToken(
                tokenType,
                accessToken.tokenValue,
                accessToken.issuedAtEpochSecond.toInstant(),
                accessToken.expiresAtEpochSecond.toInstant(),
                accessToken.scopes.toSet())
            builder.token(t) { metadata ->
                metadata.putAll(
                    accessTokenMetadata
                )
            }
        }

        val oidcIdToken = plainObject.oidcIdToken
        if (oidcIdToken != null) {
            val oidcTokenMetadata = readMap(oidcIdToken.metadata)
            @Suppress("UNCHECKED_CAST")val t = OidcIdToken(
                oidcIdToken.tokenValue,
                oidcIdToken.issuedAtEpochSecond.toInstant(),
                oidcIdToken.expiresAtEpochSecond.toInstant(),
                oidcTokenMetadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] as? Map<String, Any>
            )
            builder.token(
                t
            ) { metadata: MutableMap<String, Any> ->
                metadata.putAll(
                    oidcTokenMetadata
                )
            }
        }

        val refreshToken = plainObject.refreshToken
        if (refreshToken != null) {
            val refreshTokenMetadata = readMap(refreshToken.metadata)
            val t = OAuth2RefreshToken(
                refreshToken.tokenValue,
                refreshToken.issuedAtEpochSecond.toInstant(),
                refreshToken.expiresAtEpochSecond.toInstant()
            )
            builder.token(
                t
            ) { metadata ->
                metadata.putAll(
                    refreshTokenMetadata
                )
            }
        }
        return builder.build()
    }
}