package com.labijie.infra.oauth2

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.dataformat.smile.databind.SmileMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.labijie.infra.oauth2.MetadataTypedValue.Companion.getValue
import com.labijie.infra.oauth2.MetadataTypedValue.Companion.toMetadataValue
import com.labijie.infra.oauth2.OAuth2ServerUtils.toInstant
import com.labijie.infra.oauth2.TokenSerializableObject.Companion.asSerializable
import com.labijie.infra.oauth2.serialization.jackson.OAuth2JacksonModule
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
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
import java.security.Principal
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream


class OAuth2AuthorizationConverter private constructor() {

    companion object {
        val Instance: OAuth2AuthorizationConverter by lazy {
            OAuth2AuthorizationConverter()
        }

        private val logger by lazy {
            LoggerFactory.getLogger(OAuth2AuthorizationConverter::class.java)
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
        GZIPInputStream(`in`).use { stream ->
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


    fun writeMap(data: Map<String, Any>): ByteArray? {
        if (data.isNotEmpty()) {
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

    internal fun ITokenPlainObject.fillMetadata(metadata: MutableMap<String, Any>) {
        this.invalidated?.let {
            metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = it
        }

        this.claims?.let { claims ->

            val claimRead = mutableMapOf<String, Any?>()

            for (claim in claims) {
                if (claim.key == OAuth2Constants.CLAIM_AUD && claim.value.type == MetadataType.String) {
                    claimRead[claim.key] = (claim.value.getValue() as String).split(",")
                    continue
                }
                if (claim.key == OAuth2Constants.CLAIM_AUTHORITIES && claim.value.type == MetadataType.String) {
                    claimRead[claim.key] = (claim.value.getValue() as String).split(",")
                    continue
                }
                claimRead[claim.key] = claim.value.getValue()
            }
            metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = claimRead
        }
    }

    fun <T : AbstractOAuth2Token, TOut : ITokenPlainObject> parseToken(
        token: OAuth2Authorization.Token<T>?,
        factory: (() -> TOut),
        customizer: ((input: OAuth2Authorization.Token<T>, output: TOut) -> Unit)
    ): TOut? {

        val t = token?.token
        if (t != null && !t.tokenValue.isNullOrBlank()) {
            return factory().apply {
                this.tokenValue = t.tokenValue
                this.issuedAtEpochSecond = t.issuedAt?.epochSecond
                this.expiresAtEpochSecond = t.expiresAt?.epochSecond
                this.invalidated = token.metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] as? Boolean

                val claimValues = mutableMapOf<String, MetadataTypedValue>()
                val claims = token.metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME]
                if (claims is Map<*, *>) {
                    for (kv in claims) {
                        val key = kv.key
                        val value = kv.value
                        if (key == OAuth2Constants.CLAIM_AUD && value is Collection<*> && value.all { it is String }) {
                            val aud = value.joinToString(",")
                            claimValues[OAuth2Constants.CLAIM_AUD] = aud.toMetadataValue()
                            continue
                        }
                        if (key == OAuth2Constants.CLAIM_AUTHORITIES && value is Collection<*> && value.all { it is String }) {
                            val aud = value.joinToString(",")
                            claimValues[OAuth2Constants.CLAIM_AUTHORITIES] = aud.toMetadataValue()
                            continue
                        }
                        if (key is String && value != null) {
                            val typedValue = value.toMetadataValue()
                            claimValues[key] = typedValue
                        } else {
                            logger.error("Unsupported token claim, key: $key, value: $value")
                        }
                    }
                    this.claims = claimValues
                    customizer.invoke(token, this)
                }
            }
        }
        return null
    }

    fun <T : AbstractOAuth2Token, TOut : ITokenPlainObject> parseToken(
        token: OAuth2Authorization.Token<T>?,
        factory: (() -> TOut),
    ): TOut? {
        return parseToken(token, factory, customizer = { p1, p2 -> })
    }


    fun convertToPlain(authorization: OAuth2Authorization): AuthorizationPlainObject {
        val plainObject = AuthorizationPlainObject()

        plainObject.id = authorization.id
        plainObject.clientId = authorization.registeredClientId
        plainObject.principalName = authorization.principalName
        plainObject.grantType = authorization.authorizationGrantType.value
        plainObject.scopes = authorization.authorizedScopes

        authorization.attributes[Principal::class.java.name]?.let {

            if(it is Authentication && it.principal is ITwoFactorUserDetails) {
                plainObject.user = (it.principal as ITwoFactorUserDetails).toPlainObject()
            }else if(it is ITwoFactorUserDetails) {
                plainObject.user = it.toPlainObject()
            }
        }

//        val attributes = writeMap(authorization.attributes)
//        plainObject.attributes = attributes

        val authorizationState = authorization.getAttribute<String>(OAuth2ParameterNames.STATE)
        if (!authorizationState.isNullOrBlank()) {
            plainObject.state = authorizationState
        }

        val authorizationCode = authorization.getToken(OAuth2AuthorizationCode::class.java)
        if (authorizationCode != null) {
            plainObject.authorizationCodeToken = parseToken(authorizationCode) { TokenPlainObject() }
        }

        val accessToken = authorization.getToken(OAuth2AccessToken::class.java)
        plainObject.accessToken = parseToken(accessToken, { AccessTokenPlainObject() }) { t, o ->
            o.tokenType = t.token.tokenType.value
            if (t.token.scopes.isNotEmpty()) {
                o.scopes = t.token.scopes.toTypedArray()
            }
        }

        val oidcIdToken = authorization.getToken(OidcIdToken::class.java)
        plainObject.oidcIdToken = parseToken(oidcIdToken) { TokenPlainObject() }


        val refreshToken = authorization.refreshToken
        plainObject.refreshToken = parseToken(refreshToken) { TokenPlainObject() }

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

        val user = plainObject.user
        if(user != null) {
            builder.attribute(
                Principal::class.java.name,
                UsernamePasswordAuthenticationToken.authenticated(
                    ITwoFactorUserDetails.fromPlainObject(user),
                    null,
                    user.authorities.map { a-> SimpleGrantedAuthority(a) })
            )
        }else {
            builder.attribute(Principal::class.java.name,
                UsernamePasswordAuthenticationToken.authenticated(
                    SimplePrincipal(plainObject.principalName),
                    null,
                    listOf()
                ))
        }

        builder.id(plainObject.id)
            .principalName(plainObject.principalName)
            .authorizationGrantType(AuthorizationGrantType(plainObject.grantType))
            .authorizedScopes(plainObject.scopes)
            .principalName(plainObject.principalName)
//            .attributes {
//                it.putAll(attributes)
//            }

        val state = plainObject.state
        if (!state.isNullOrBlank()) {
            builder.attribute(OAuth2ParameterNames.STATE, state)
        }


        val code = plainObject.authorizationCodeToken
        if (code != null) {
            val authorizationCode = OAuth2AuthorizationCode(
                code.tokenValue,
                code.issuedAtEpochSecond.toInstant(),
                code.expiresAtEpochSecond.toInstant()
            )
            builder.token(
                authorizationCode
            ) { metadata ->
                code.fillMetadata(metadata)
            }
        }

        val accessToken = plainObject.accessToken
        if (accessToken != null) {
            var tokenType: OAuth2AccessToken.TokenType? = null
            when (accessToken.tokenType) {
                OAuth2AccessToken.TokenType.BEARER.value -> tokenType = OAuth2AccessToken.TokenType.BEARER
                OAuth2AccessToken.TokenType.DPOP.value -> tokenType = OAuth2AccessToken.TokenType.DPOP
            }
            val t = OAuth2AccessToken(
                tokenType,
                accessToken.tokenValue,
                accessToken.issuedAtEpochSecond.toInstant(),
                accessToken.expiresAtEpochSecond.toInstant(),
                accessToken.scopes.toSet()
            )
            builder.token(t) { metadata ->
                accessToken.fillMetadata(metadata)
            }
        }

        val oidcIdToken = plainObject.oidcIdToken
        if (oidcIdToken != null) {
            val token = OidcIdToken.withTokenValue(oidcIdToken.tokenValue)
                .issuedAt(oidcIdToken.issuedAtEpochSecond.toInstant())
                .expiresAt(oidcIdToken.expiresAtEpochSecond.toInstant())
                .build()
            builder.token(
                token
            ) { metadata: MutableMap<String, Any> ->
                oidcIdToken.fillMetadata(metadata)
            }
        }

        val refreshToken = plainObject.refreshToken
        if (refreshToken != null) {
            val t = OAuth2RefreshToken(
                refreshToken.tokenValue,
                refreshToken.issuedAtEpochSecond.toInstant(),
                refreshToken.expiresAtEpochSecond.toInstant()
            )
            builder.token(
                t
            ) { metadata ->
                refreshToken.fillMetadata(metadata)
            }
        }
        return builder.build()
    }
}