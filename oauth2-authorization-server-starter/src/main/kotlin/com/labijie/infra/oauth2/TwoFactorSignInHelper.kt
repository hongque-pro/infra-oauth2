package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.authentication.JwtUtils
import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.oauth2.events.UserSignedInEvent
import com.labijie.infra.utils.ifNullOrBlank
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationEventPublisher
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import java.security.Principal
import java.util.HashSet

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class TwoFactorSignInHelper(
    private val clientRepository: RegisteredClientRepository,
    private val serverProperties: OAuth2ServerProperties,
    private val eventPublisher: ApplicationEventPublisher,
    private val jwtEncoder: JwtEncoder,
    private val jwtDecoder: JwtDecoder,
    private val jwtCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>,
    private val identityService: IIdentityService,
): ApplicationContextAware {

    companion object {
        private val LOGGER = LoggerFactory.getLogger(TwoFactorSignInHelper::class.java)
    }

    private lateinit var context: ApplicationContext

    private lateinit var authenticationManager: AuthenticationManager
    private lateinit var authorizationService: OAuth2AuthorizationService

    fun setup(authenticationManager: AuthenticationManager, authorizationService: OAuth2AuthorizationService){
        this.authenticationManager = authenticationManager
        this.authorizationService = authorizationService
    }


    fun signIn(
        clientId: String,
        userName: String,
        twoFactorGranted: Boolean = false,
        scopes: Set<String> = hashSetOf()
    ): OAuth2AccessTokenAuthenticationToken {
        if(userName.isBlank()){
            throw UsernameNotFoundException("User with name '${userName.ifNullOrBlank { "<empty>" }}' was not found")
        }

        val user = identityService.getUserByName(userName)

        val client = clientRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)

        return signIn(
            client,
            user.username,
            twoFactorGranted,
            scopes,
            null
        )
    }


    fun signIn(
        clientId: String,
        user: ITwoFactorUserDetails,
        twoFactorGranted: Boolean = false,
        scopes: Set<String> = hashSetOf()
    ): OAuth2AccessTokenAuthenticationToken {
        if (!user.isTwoFactorEnabled() && twoFactorGranted) {
            throw IllegalArgumentException("SignIn user isTwoFactorEnabled = false, but twoFactorGranted be set to true.")
        }

        val client = clientRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)

        return signIn(
            client,
            user.username,
            twoFactorGranted,
            scopes,
            null
        )
    }


    fun signIn(
        registeredClient: RegisteredClient,
        username: String,
        twoFactorGranted: Boolean = false,
        scopes: Set<String> = hashSetOf(),
        password: String? = null
    ): OAuth2AccessTokenAuthenticationToken {
        return try {
            val userAuthentication = if(password != null){
                val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(username, password)
                if (LOGGER.isDebugEnabled) {
                    LOGGER.debug("got usernamePasswordAuthenticationToken=$usernamePasswordAuthenticationToken")
                }
                val r =  authenticationManager.authenticate(usernamePasswordAuthenticationToken)
                val principal = (r.principal as? ITwoFactorUserDetails)?.withoutPassword()
                if(principal != null){
                    //尽量移除密码信息
                    UsernamePasswordAuthenticationToken(principal, null)
                }else{
                    r
                }
            }else{
                val user = identityService.getUserByName(username).withoutPassword()
                UsernamePasswordAuthenticationToken(user, null)
            }


            var authorizedScopes = registeredClient.scopes ?: HashSet() // Default to configured scopes
            if (scopes.isNotEmpty() && registeredClient.scopes.isNotEmpty()) { //没有配置 scope 认为忽略
                val unauthorizedScopes: Set<String> = scopes
                    .filter { requestedScope -> !registeredClient.scopes.contains(requestedScope) }
                    .toSet()
                if (unauthorizedScopes.isNotEmpty()) {
                    throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE)
                }
                authorizedScopes = scopes
            }
            val issuer = serverProperties.issuer

            val headersBuilder: JoseHeader.Builder = JwtUtils.headers()
            val claimsBuilder: JwtClaimsSet.Builder = JwtUtils.accessTokenClaims(
                registeredClient, issuer, registeredClient.clientId, authorizedScopes
            )
            val context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
                .registeredClient(registeredClient)
                .principal(userAuthentication)
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .put(Constants.CLAIM_TWO_FACTOR, twoFactorGranted)
                //.authorizationGrant(resourceOwnerPasswordAuthentication)
                .build()
            jwtCustomizer.customize(context)


            val headers = context.headers.build()
            val claims = context.claims.build()
            val jwtAccessToken = jwtEncoder.encode(headers, claims)

            // Use the scopes after customizing the token
            authorizedScopes = claims.getClaim(OAuth2ParameterNames.SCOPE) ?: HashSet()
            val accessToken = OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwtAccessToken.tokenValue,
                jwtAccessToken.issuedAt,
                jwtAccessToken.expiresAt,
                authorizedScopes
            )
            var refreshToken: OAuth2RefreshToken? = null
            if (registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
                refreshToken =
                    OAuth2ServerUtils.generateRefreshToken(registeredClient.tokenSettings.refreshTokenTimeToLive)
            }
            val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(registeredClient.clientId)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .token<OAuth2Token>(
                    accessToken
                ) { metadata: MutableMap<String?, Any?> ->
                    metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = jwtAccessToken.claims
                }
                .attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
                .attribute(Principal::class.java.name, userAuthentication)
            if (refreshToken != null) {
                authorizationBuilder.refreshToken(refreshToken)
            }
            val authorization = authorizationBuilder.build()
            authorizationService.save(authorization)
            if (LOGGER.isDebugEnabled) {
                LOGGER.debug("OAuth2Authorization saved successfully")
            }
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
            if (LOGGER.isDebugEnabled) {
                LOGGER.debug("returning OAuth2AccessTokenAuthenticationToken")
            }
            val token = OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                userAuthentication,
                accessToken,
                refreshToken,
                tokenAdditionalParameters
            )
            token.isAuthenticated = true

            eventPublisher.publishEvent(UserSignedInEvent(this, token))
            token
        } catch (ex: Exception) {
            LOGGER.error("problem in authenticate", ex)
            throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), ex)
        }
    }

    fun signInTwoFactor(): OAuth2AccessTokenAuthenticationToken {
        val au = SecurityContextHolder.getContext().authentication
        if(au == null || !au.isAuthenticated){
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN)
        }
        val value = OAuth2Utils.getTokenValue(au)
        val token = jwtDecoder.decode(value)
        val client = token.claims[JwtClaimNames.SUB]?.toString() ?: ""
        val scopeNames = (token.claims[OAuth2ParameterNames.SCOPE]?.toString() ?: "").split(",").filter { it.isNotBlank() }.toSet()
        val username = (token.claims[Constants.CLAIM_USER_NAME]?.toString() ?: "")
        return signIn(client, username, true, scopeNames)
    }

//    fun signInTwoFactorAsync(): Mono<OAuth2AccessToken> {
//        return ReactiveSecurityContextHolder.getContext().map {
//            val auth = SecurityContextHolder.getContext().authentication as? OAuth2Authentication
//            val token = signInTwoFactorCore(auth)
//            token
//        }
//    }

    fun signOut() {
        val auth = SecurityContextHolder.getContext().authentication as? OAuth2Authorization
        if (auth != null) {
            authorizationService.remove(auth)
        }
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        context = applicationContext
    }
}