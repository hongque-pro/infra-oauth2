package com.labijie.infra.oauth2

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.dataformat.smile.databind.SmileMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.labijie.infra.oauth2.OAuth2ServerUtils.toInstant
import com.labijie.infra.oauth2.serialization.jackson.OAuth2JacksonModule
import org.springframework.security.jackson2.CoreJackson2Module
import org.springframework.security.oauth2.core.AbstractOAuth2Token
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import org.springframework.security.web.jackson2.WebJackson2Module
import org.springframework.security.web.jackson2.WebServletJackson2Module
import org.springframework.security.web.server.jackson2.WebServerJackson2Module
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import kotlin.reflect.KClass
import kotlin.reflect.full.createInstance


class OAuth2AuthorizationConverter private constructor() {

    companion object {
        val Instance: OAuth2AuthorizationConverter by lazy {
            OAuth2AuthorizationConverter()
        }
    }


    fun compress(data: ByteArray): ByteArray? {
        if (data.isEmpty()) {
            return data
        }
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use {
            it.write(data)
        }

        return out.toByteArray()
    }

    fun uncompress(bytes: ByteArray): ByteArray? {
        if (bytes.isEmpty()) {
            return bytes
        }
        val out = ByteArrayOutputStream()
        val `in` = ByteArrayInputStream(bytes)
        GZIPInputStream(`in`).use {
            stream->
            val buffer = ByteArray(256)
            var n: Int
            while ((stream.read(buffer).also { n = it }) >= 0) {
                out.write(buffer, 0, n)
            }
            return out.toByteArray()
        }
    }

    val objectMapper: ObjectMapper by lazy {
        SmileMapper.builder()
            .configure(JsonGenerator.Feature.WRITE_BIGDECIMAL_AS_PLAIN, true)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.WRITE_ENUMS_USING_INDEX, true)
            //.setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .build()
            .apply {
                //spring CAS module BUG
//            val classLoader = JdbcOAuth2AuthorizationService::class.java.classLoader
//            val securityModules = SecurityJackson2Modules.getModules(classLoader)
//            this.registerModules(securityModules)
                this.deactivateDefaultTyping()
                this.registerModule(OAuth2AuthorizationServerJackson2Module())
                this.registerModule(OAuth2JacksonModule())

                //TODO: wait spring fix CAS module
                //this.activateDefaultTyping(PolymorphicTypeValidator.Validity.ALLOWED, JsonTypeInfo.As.PROPERTY)
                this.registerModule(JavaTimeModule())
                this.registerModule(CoreJackson2Module())
                this.registerModule(WebJackson2Module())
                this.registerModule(WebServletJackson2Module())
                this.registerModule(WebServerJackson2Module())
//            this.registerModule(OAuth2ClientJackson2Module())
//            this.registerModule(Saml2Jackson2Module())
            }
    }


    private fun writeMap(data: Map<String, Any>): ByteArray? {
        if(data.isNotEmpty()) {
            return try {
                objectMapper.writeValueAsBytes(data)
            } catch (ex: Exception) {
                throw IllegalArgumentException(ex.message, ex)
            }
        }
        return null
    }

    private fun readMap(data: ByteArray?): Map<String, Any> {
        if (data == null) {
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


    fun convertToPlain(authorization: OAuth2Authorization): AuthorizationPlainObject {
        val plainObject = AuthorizationPlainObject()

        plainObject.id = authorization.id
        plainObject.clientId = authorization.registeredClientId
        plainObject.principalName = authorization.principalName
        plainObject.grantType = authorization.authorizationGrantType.value

        val attributes = writeMap(authorization.attributes)
        plainObject.attributes = attributes

        val authorizationState = authorization.getAttribute<String>(OAuth2ParameterNames.STATE)
        if (!authorizationState.isNullOrBlank()) {
            plainObject.state = authorizationState
        }

        val authorizationCode = authorization.getToken(OAuth2AuthorizationCode::class.java)
        if (authorizationCode != null) {
            plainObject.authorizationCodeToken = parseToken(authorizationCode, TokenPlainObject::class)
        }

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

    fun convertFromPlain(plainObject: AuthorizationPlainObject): OAuth2Authorization {

        val client = RegisteredClient.withId(plainObject.clientId)
            .clientId(plainObject.clientId)
            .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://localhost")
            .build()
        val builder = OAuth2Authorization.withRegisteredClient(client)
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
                accessToken.scopes.toSet()
            )
            builder.token(t) { metadata ->
                metadata.putAll(
                    accessTokenMetadata
                )
            }
        }

        val oidcIdToken = plainObject.oidcIdToken
        if (oidcIdToken != null) {
            val oidcTokenMetadata = readMap(oidcIdToken.metadata)
            @Suppress("UNCHECKED_CAST") val t = OidcIdToken(
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