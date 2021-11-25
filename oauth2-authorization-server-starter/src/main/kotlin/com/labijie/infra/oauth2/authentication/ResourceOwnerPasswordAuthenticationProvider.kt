package com.labijie.infra.oauth2.authentication

import com.labijie.infra.oauth2.RefreshTokenSerializer
import com.labijie.infra.oauth2.events.UserSignedInEvent
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationEventPublisher
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jwt.JoseHeader
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import java.security.Principal
import java.time.Duration
import java.time.Instant
import java.util.*


class ResourceOwnerPasswordAuthenticationProvider(
    private val authenticationManager: AuthenticationManager,
    private val authorizationService: OAuth2AuthorizationService,
    private val jwtEncoder: JwtEncoder,
    private val jwtCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>,
    private val providerSettings: ProviderSettings,
    private val eventPublisher: ApplicationEventPublisher?
) : AuthenticationProvider {


    companion object {
        private val LOGGER = LoggerFactory.getLogger(ResourceOwnerPasswordAuthenticationProvider::class.java)
    }


    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val resourceOwnerPasswordAuthentication = authentication as ResourceOwnerPasswordAuthenticationToken
        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(resourceOwnerPasswordAuthentication)
        val registeredClient = clientPrincipal.registeredClient
        if (!registeredClient!!.authorizationGrantTypes.contains(AuthorizationGrantType.PASSWORD)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }
        val additionalParameters: Map<String, Any> = resourceOwnerPasswordAuthentication.additionalParameters
        val username = additionalParameters[OAuth2ParameterNames.USERNAME] as? String
        val password = additionalParameters[OAuth2ParameterNames.PASSWORD] as? String

        if (username.isNullOrBlank() || password.isNullOrBlank()) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN)
        }

        return try {
            val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(username, password)
            if (LOGGER.isDebugEnabled) {
                LOGGER.debug("got usernamePasswordAuthenticationToken=$usernamePasswordAuthenticationToken")
            }
            val usernamePasswordAuthentication =
                authenticationManager.authenticate(usernamePasswordAuthenticationToken)

            var authorizedScopes = registeredClient.scopes ?: setOf() // Default to configured scopes
            if (resourceOwnerPasswordAuthentication.scopes.isNotEmpty() && registeredClient.scopes.isNotEmpty()) { //没有配置 scope 认为忽略
                val unauthorizedScopes: Set<String> = resourceOwnerPasswordAuthentication.scopes
                    .filter { requestedScope -> !registeredClient.scopes.contains(requestedScope) }
                    .toSet()
                if (unauthorizedScopes.isNotEmpty()) {
                    throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE)
                }
                authorizedScopes = resourceOwnerPasswordAuthentication.scopes
            }
            val issuer = providerSettings.issuer

            val headersBuilder: JoseHeader.Builder = JwtUtils.headers()
            val claimsBuilder: JwtClaimsSet.Builder = JwtUtils.accessTokenClaims(
                registeredClient, issuer, clientPrincipal.name, authorizedScopes
            )
            val context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthentication)
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(resourceOwnerPasswordAuthentication)
                .build()
            jwtCustomizer.customize(context)
            val headers = context.headers.build()
            val claims = context.claims.build()
            val jwtAccessToken = jwtEncoder.encode(headers, claims)

            // Use the scopes after customizing the token
            authorizedScopes = claims.getClaim(OAuth2ParameterNames.SCOPE) ?: setOf()
            val accessToken = OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwtAccessToken.tokenValue,
                jwtAccessToken.issuedAt,
                jwtAccessToken.expiresAt,
                authorizedScopes
            )
            var refreshToken: OAuth2RefreshToken? = null
            if (registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
                refreshToken = generateRefreshToken(registeredClient.tokenSettings.refreshTokenTimeToLive)
            }
            val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.name)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .token<OAuth2Token>(
                    accessToken
                ) { metadata: MutableMap<String?, Any?> ->
                    metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = jwtAccessToken.claims
                }
                .attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
                .attribute(Principal::class.java.name, usernamePasswordAuthentication)
            if (refreshToken != null) {
                authorizationBuilder.refreshToken(refreshToken)
            }
            val authorization = authorizationBuilder.build()
            authorizationService.save(authorization)
            LOGGER.debug("OAuth2Authorization saved successfully")
            val tokenAdditionalParameters: MutableMap<String, Any> = HashMap()
            claims.claims.forEach { (key: String, value: Any) ->
                if (key != OAuth2ParameterNames.SCOPE &&
                    key != JwtClaimNames.IAT &&
                    key != JwtClaimNames.EXP &&
                    key != JwtClaimNames.NBF
                ) {
                    tokenAdditionalParameters[key] = value
                }
            }
            LOGGER.debug("returning OAuth2AccessTokenAuthenticationToken")
            val token = OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                usernamePasswordAuthentication,
                accessToken,
                refreshToken,
                tokenAdditionalParameters
            )
            token.isAuthenticated = true

            eventPublisher?.publishEvent(UserSignedInEvent(this, token))
            token
        } catch (ex: Exception) {
            LOGGER.error("problem in authenticate", ex)
            throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), ex)
        }
    }

    override fun supports(authentication: Class<*>): Boolean {
        val supports: Boolean =
            ResourceOwnerPasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
        LOGGER.debug("supports authentication=$authentication returning $supports")
        return supports
    }

    private fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
        var clientPrincipal: OAuth2ClientAuthenticationToken? = null
        if (OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication.principal::class.java)) {
            clientPrincipal = authentication.principal as? OAuth2ClientAuthenticationToken
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
            return clientPrincipal
        }
        throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
    }

    private fun generateRefreshToken(tokenTimeToLive: Duration): OAuth2RefreshToken? {
        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(tokenTimeToLive)
        return OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, expiresAt)
    }

}