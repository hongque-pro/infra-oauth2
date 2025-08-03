package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.utils.ifNullOrBlank
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.util.StringUtils
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.concurrent.TimeUnit

object OAuth2ServerUtils {

    fun createDefaultClientRegistration(properties: OAuth2ServerProperties): RegisteredClient {

        val tokenSettings = TokenSettings.builder().accessTokenTimeToLive(properties.serverClient.defaultClient.accessTokenExpiration)
            .refreshTokenTimeToLive(properties.serverClient.defaultClient.refreshTokenExpiration)
            .reuseRefreshTokens(properties.serverClient.defaultClient.reuseRefreshToken)
            .build()


        return RegisteredClient.withId(properties.serverClient.defaultClient.clientId)
            .clientId(properties.serverClient.defaultClient.clientId)
            .clientName("infra_default")
            .clientSecret(properties.serverClient.defaultClient.secret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(OAuth2Utils.PASSWORD_GRANT_TYPE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .tokenSettings(tokenSettings)
            .build()
    }

    fun Long?.toInstant(unit: TimeUnit = TimeUnit.SECONDS): Instant? {
        if (this == null) {
            return null
        }
        val seconds = unit.toSeconds(this)
        return Instant.ofEpochSecond(seconds)
    }

    fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

    fun String.md5Hex(): String {
        val md = MessageDigest.getInstance("md5");
        return md.digest(this.toByteArray(Charsets.UTF_8)).toHexString()
    }

    fun generateRefreshToken(tokenTimeToLive: Duration): OAuth2RefreshToken {
        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(tokenTimeToLive)
        return OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, expiresAt)
    }

    fun OAuth2AccessTokenAuthenticationToken.toAccessToken(): AccessToken {
        val accessToken = AccessToken().also { it ->
            it.accessToken = accessToken.tokenValue
            it.tokenType = this.accessToken.tokenType.value
            it.expiresIn = accessToken.getExpiresInSeconds()
            if (this.accessToken.scopes.isNotEmpty()) {
                it.scope = StringUtils.collectionToDelimitedString(this.accessToken.scopes, " ")
            }
            if (this.refreshToken != null) {
                it.refreshToken = this.refreshToken!!.tokenValue
            }

            if (this.additionalParameters.isNotEmpty()) {
                for (parameter in this.additionalParameters) {
                    when (parameter.key) {
                        OAuth2Constants.CLAIM_AUTHORITIES-> {
                            val list = additionalParameters[OAuth2Constants.CLAIM_AUTHORITIES] as? List<*>
                            if(list != null){
                                it.authorities.addAll(list.map { g-> g.toString() })
                            }
                        }
                        OAuth2Constants.CLAIM_USER_NAME -> {
                            it.username = parameter.value.toString()
                        }

                        OAuth2Constants.CLAIM_USER_ID -> {
                            it.userId = parameter.value.toString()
                        }

                        OAuth2Constants.CLAIM_TWO_FACTOR -> {
                            it.twoFactorGranted = parameter.value.toString().toBooleanStrict()
                        }
                        OAuth2ParameterNames.ACCESS_TOKEN,
                        OAuth2ParameterNames.TOKEN_TYPE,
                        OAuth2ParameterNames.EXPIRES_IN,
                        OAuth2ParameterNames.SCOPE,
                        OAuth2ParameterNames.REFRESH_TOKEN -> continue
                        else -> {
                            it.details.putIfAbsent(parameter.key, parameter.value)
                        }
                    }
                }
            }

        }
        return accessToken
    }

    fun OAuth2AccessToken.getExpiresInSeconds(): Long {
        return if (this.expiresAt != null) {
            ChronoUnit.SECONDS.between(Instant.now(), this.expiresAt)
        } else -1
    }

    fun OAuth2AccessTokenAuthenticationToken.toMap(): Map<String, Any> {

        val parameters: MutableMap<String, Any> = HashMap()
        parameters[OAuth2ParameterNames.ACCESS_TOKEN] = accessToken.tokenValue
        parameters[OAuth2ParameterNames.TOKEN_TYPE] = accessToken.tokenType.value
        parameters[OAuth2ParameterNames.EXPIRES_IN] = getExpiresIn(accessToken)
        if (accessToken.scopes.isNotEmpty()) {
            parameters[OAuth2ParameterNames.SCOPE] =
                StringUtils.collectionToDelimitedString(accessToken.scopes, " ")
        }
        val refreshTv = refreshToken?.tokenValue
        if (!refreshTv.isNullOrBlank()) {
            parameters[OAuth2ParameterNames.REFRESH_TOKEN] = refreshTv
        }
        val params = additionalParameters
        if (params.isNotEmpty()) {
            for ((key, value) in params.entries) {
                parameters[key] = value
            }
        }
        return parameters
    }

    private fun getExpiresIn(token: AbstractOAuth2Token): Long {
        return if (token.expiresAt != null) {
            ChronoUnit.SECONDS.between(Instant.now(), token.expiresAt)
        } else -1
    }

    fun OAuth2Authorization.tokenId(): String {
        val authorization = this
        val accessToken = authorization.getToken(OAuth2AccessToken::class.java)?.token?.tokenValue
        if (!accessToken.isNullOrBlank()) {
            return accessToken.md5Hex()
        }

        val authorizationCode = authorization.getToken(OAuth2AuthorizationCode::class.java)?.token?.tokenValue
        if (!authorizationCode.isNullOrBlank()) {
            return authorizationCode.md5Hex()
        }

        val oidcIdToken = authorization.getToken(OidcIdToken::class.java)?.token?.tokenValue
        if (!oidcIdToken.isNullOrBlank()) {
            return oidcIdToken.md5Hex()
        }

        return authorization.id
    }

    val Jwt.isExpired
        get() = this.expiresAt != null && this.expiresAt!!.epochSecond <= Instant.now().epochSecond

    private fun Map<String, *>.getScopes(): Set<String> {
        val scope = this.getOrDefault(OAuth2ParameterNames.SCOPE, null) ?: return hashSetOf()
        if (scope is String) {
            return StringUtils.commaDelimitedListToSet(scope)
        }
        if (scope is Collection<*>) {
            val set = hashSetOf<String>()
            scope.forEach {
                if (it != null) {
                    set.add(it.toString())
                }
            }
            return set
        }
        return Collections.singleton(scope.toString())
    }


    fun Jwt.getScopes(): Set<String> {
        return this.claims.getScopes()
    }

    fun JwtClaimsSet.getScopes(): Set<String> {
        return this.claims.getScopes()
    }

    fun ITwoFactorUserDetails.toPrincipal(): TwoFactorPrincipal {
        return TwoFactorPrincipal(
            getUserId(),
            username,
            getTokenAttributes().getOrDefault(OAuth2Constants.CLAIM_TWO_FACTOR, "false").toBoolean(),
            authorities.toMutableList(),
            getTokenAttributes().filter { !isWellKnownClaim(it.key) }
        )
    }

//    fun OAuth2ServerProperties.getIssuerOrDefault(): String {
//        val issuer = this.issuer?.toString()
//        return issuer.ifNullOrBlank { "http://localhost" }
//    }

    internal const val DEFAULT_ISSUER = "http://localhost"

    fun AuthorizationServerSettings.getIssuerOrDefault(): String {
        return this.issuer.ifNullOrBlank { DEFAULT_ISSUER }
    }
}