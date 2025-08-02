package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.OAuth2ServerUtils.getIssuerOrDefault
import com.labijie.infra.oauth2.OAuth2ServerUtils.getScopes
import com.labijie.infra.oauth2.authentication.JwtUtils
import com.labijie.infra.oauth2.customizer.TwoFactorGrantedAuthentication
import com.labijie.infra.oauth2.events.UserSignedInEvent
import com.labijie.infra.utils.ifNullOrBlank
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationEventPublisher
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.web.util.UrlUtils
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import java.security.Principal

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class TwoFactorSignInHelper(
    private val jwtGenerator: JwtGenerator,
    private val jwtCodec: IOAuth2ServerJwtCodec,
    private val clientRepository: RegisteredClientRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val identityService: IIdentityService,
) : ApplicationContextAware {

    companion object {
        private val LOGGER = LoggerFactory.getLogger(TwoFactorSignInHelper::class.java)

        private fun HttpServletRequest.getCleanRequestUrl(): String {
            val schema = this.getHeader("X-Forwarded-Proto").ifNullOrBlank { this.scheme }

            val host = this.getHeader("X-Forwarded-Host").ifNullOrBlank { this.serverName }

            val port = if(this.getHeader("X-Forwarded-Proto").isNullOrBlank()) this.serverPort else (if(schema.equals("https", ignoreCase = true)) 443 else 80)

            return UrlUtils.buildFullRequestUrl(schema, host, port, this.requestURI, null)
        }
    }

    private lateinit var context: ApplicationContext


    private val authorizationService: OAuth2AuthorizationService by lazy {
        context.getBean(OAuth2AuthorizationService::class.java)
    }

    private val authorizationServerSettings: AuthorizationServerSettings by lazy {
        context.getBean(AuthorizationServerSettings::class.java)
    }

    private val tokenGenerator by lazy {
        context.getBean(OAuth2TokenGenerator::class.java)

    }


    protected class DefaultAuthorizationServerContext(
        private val authorizationServerSettings: AuthorizationServerSettings
    ) : AuthorizationServerContext {

        override fun getIssuer(): String {
            val issuer = authorizationServerSettings.getIssuerOrDefault()
            return issuer
        }

        override fun getAuthorizationServerSettings(): AuthorizationServerSettings {
            return this.authorizationServerSettings
        }
    }


    private fun getUser(userName: String?): ITwoFactorUserDetails {
        if (userName.isNullOrBlank()) {
            throw UsernameNotFoundException("User with name '${userName.ifNullOrBlank { "<empty>" }}' was not found")
        }

        return identityService.getUserByName(userName)
            ?: throw UsernameNotFoundException("User with name '${userName.ifNullOrBlank { "<empty>" }}' was not found")
    }

    fun signIn(
        clientId: String,
        userName: String,
        twoFactorGranted: Boolean = false,
        scopes: Set<String>? = null,
        request: HttpServletRequest? = null
    ): OAuth2AccessTokenAuthenticationToken {
        val user = getUser(userName)


        val client = clientRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)

        return signIn(
            client,
            user,
            twoFactorGranted,
            scopes,
            request
        )
    }

    fun signIn(
        client: RegisteredClient,
        userName: String,
        twoFactorGranted: Boolean = false,
        scopes: Set<String>? = null,
        request: HttpServletRequest? = null
    ): OAuth2AccessTokenAuthenticationToken {

        val user = getUser(userName)

        return signIn(
            client,
            user,
            twoFactorGranted,
            scopes,
            request
        )
    }

    fun signIn(
        clientId: String,
        user: ITwoFactorUserDetails,
        twoFactorGranted: Boolean = false,
        scopes: Set<String>? = null,
        request: HttpServletRequest? = null
    ): OAuth2AccessTokenAuthenticationToken {

        val client = clientRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)

        return signIn(
            client,
            user,
            twoFactorGranted,
            scopes,
            request
        )
    }

    fun signIn(
        client: RegisteredClient,
        user: ITwoFactorUserDetails,
        twoFactorGranted: Boolean = false,
        scopes: Set<String>? = null,
        request: HttpServletRequest? = null
    ): OAuth2AccessTokenAuthenticationToken {
        if (!user.isTwoFactorEnabled() && twoFactorGranted) {
            throw IllegalArgumentException("SignIn user isTwoFactorEnabled = false, but twoFactorGranted be set to true.")
        }
        val u = user.withoutPassword()
        val aut = if (twoFactorGranted) TwoFactorGrantedAuthentication(u) else UsernamePasswordAuthenticationToken(u, null)
        return signInCore(client, aut, scopes ?: client.scopes, request)
    }

    fun signIn(
        clientId: String,
        username: String,
        password: String,
        twoFactorGranted: Boolean = false,
        scopes: Set<String>? = null,
        request: HttpServletRequest? = null
    ): OAuth2AccessTokenAuthenticationToken {

        val client = clientRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)

        return signIn(client, username, password, twoFactorGranted, scopes ?: client.scopes, request)
    }

    fun signIn(
        client: RegisteredClient,
        username: String,
        password: String,
        twoFactorGranted: Boolean = false,
        scopes: Set<String>? = null,
        request: HttpServletRequest? = null
    ): OAuth2AccessTokenAuthenticationToken {

        val auth = createUserAuthenticationToken(username, password, twoFactorGranted)
        return signInCore(client, auth, scopes ?: client.scopes, request)
    }

    private val daoAuthenticationProvider by lazy {
        val providerBean = context.getBeanProvider(DaoAuthenticationProvider::class.java).ifAvailable

        if (providerBean != null) {
            providerBean
        } else {

            val passwordEncoder = context.getBean(PasswordEncoder::class.java)
            val userDetailsService = context.getBean(UserDetailsService::class.java)

            DaoAuthenticationProvider(userDetailsService).apply {
                setPasswordEncoder(passwordEncoder)
            }
        }
    }

    private fun generateJwtAccessToken(
        registeredClient: RegisteredClient,
        principal: Authentication,
        scopes: Set<String>,
        serverContext: AuthorizationServerContext
    ): Jwt {
        val headersBuilder = JwtUtils.headers()
        val claimsBuilder = JwtUtils.accessTokenClaims(serverContext.issuer, registeredClient, principal.name, scopes)

        val context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
            .registeredClient(registeredClient)
            .authorizationServerContext(serverContext)
            .principal(principal)
            .authorizedScopes(scopes)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(OAuth2Utils.PASSWORD_GRANT_TYPE)
            .build()

        return jwtGenerator.generate(context)
            ?: throw IllegalStateException("Failed to generate JWT access token.")
    }


    private fun signInCore(
        registeredClient: RegisteredClient,
        userAuthentication: Authentication,
        scopes: Set<String> = hashSetOf(),
        request: HttpServletRequest? = null
    ): OAuth2AccessTokenAuthenticationToken {
        return try {
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

            val serverCtx = AuthorizationServerContextHolder.getContext() ?: DefaultAuthorizationServerContext(authorizationServerSettings)

            val jwtAccessToken = generateJwtAccessToken(registeredClient, userAuthentication, authorizedScopes, serverCtx)

            val claims = jwtAccessToken.claims
            // Use the scopes after customizing the token
            authorizedScopes = jwtAccessToken.getScopes()

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
                .authorizationGrantType(OAuth2Utils.PASSWORD_GRANT_TYPE)
                .token<OAuth2Token>(
                    accessToken
                ) { metadata: MutableMap<String?, Any?> ->
                    metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = jwtAccessToken.claims
                }
                .attribute(OAuth2Constants.CLAIM_SCOPE, authorizedScopes)
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
            claims.forEach { (key: String, value: Any) ->
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

            val requestAttribute =
                request ?: (RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes)?.request
            eventPublisher.publishEvent(UserSignedInEvent(this, token, requestAttribute))
            token
        } catch (ex: Exception) {
            processException(ex)
        }
    }

    private fun processException(ex: Exception): Nothing {
        when (ex) {
            is BadCredentialsException -> {
                val error = OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "User name or password is incorrect.", null)
                throw OAuth2AuthenticationException(error, ex)
            }

            is OAuth2AuthenticationException -> {
                throw ex
            }

            is AuthenticationException -> {
                val error = OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, ex.message, null)
                throw OAuth2AuthenticationException(error, ex)
            }

            else -> {
                LOGGER.error("problem in sign in", ex)
                throw OAuth2AuthenticationException(
                    OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR,
                        "Unhandled error has occurred when sign in.",
                        null
                    ), ex
                )
            }
        }
    }



    private fun createUserAuthenticationToken(
        username: String,
        password: String,
        twoFactorGranted: Boolean,
    ): Authentication {

        val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(username, password)
        if (LOGGER.isDebugEnabled) {
            LOGGER.debug("Got usernamePasswordAuthenticationToken=$usernamePasswordAuthenticationToken")
        }

        val r = try {
            //usernamePasswordAuthenticationToken.isAuthenticated = true
            //authenticationManager.authenticate(usernamePasswordAuthenticationToken)
            daoAuthenticationProvider.authenticate(usernamePasswordAuthenticationToken)
        } catch (ex: Exception) {
            processException(ex)
        }
        val principal = (r.principal as? ITwoFactorUserDetails)?.withoutPassword()
        return if (principal != null) {
            if(twoFactorGranted) {
                TwoFactorGrantedAuthentication(principal)
            }else {
                //尽量移除密码信息
                UsernamePasswordAuthenticationToken(principal, null)
            }
        } else {
            UsernamePasswordAuthenticationToken(r.principal, null)
        }
    }

    fun signInTwoFactor(): OAuth2AccessTokenAuthenticationToken {
        val au = SecurityContextHolder.getContext().authentication
        if (au == null || !au.isAuthenticated) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN)
        }
        val value = OAuth2Utils.getTokenValue(au) ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN)
        val token = jwtCodec.decode(value)
        val aud = token.claims[OAuth2Constants.CLAIM_AUD]
        val clientId = if (aud != null && aud is Collection<*>) {
            aud.firstOrNull()?.toString() ?: ""
        } else ""
        val scopeNames = token.getScopes()
        val username = (token.claims[OAuth2Constants.CLAIM_USER_NAME]?.toString() ?: "")
        return signIn(clientId, username, true, scopeNames)
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