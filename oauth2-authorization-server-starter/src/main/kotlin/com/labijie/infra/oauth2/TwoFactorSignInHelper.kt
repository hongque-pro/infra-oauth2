//package com.labijie.infra.oauth2
//
//import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
//import com.labijie.infra.oauth2.events.UserSignedInEvent
//import com.labijie.infra.oauth2.token.TwoFactorAuthenticationConverter
//import org.springframework.context.ApplicationEventPublisher
//import org.springframework.security.authentication.BadCredentialsException
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
//import org.springframework.security.core.Authentication
//import org.springframework.security.core.GrantedAuthority
//import org.springframework.security.core.authority.SimpleGrantedAuthority
//import org.springframework.security.core.context.SecurityContextHolder
//import org.springframework.security.oauth2.common.OAuth2AccessToken
//import org.springframework.security.oauth2.core.OAuth2AccessToken
//import org.springframework.security.oauth2.provider.AuthorizationRequest
//import org.springframework.security.oauth2.provider.ClientDetailsService
//import org.springframework.security.oauth2.provider.OAuth2Authentication
//import org.springframework.security.oauth2.provider.OAuth2RequestFactory
//import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices
//import org.springframework.security.oauth2.provider.token.DefaultTokenServices
//import org.springframework.security.oauth2.provider.token.TokenStore
//
///**
// * Created with IntelliJ IDEA.
// * @author Anders Xiao
// * @date 2019-02-21
// */
//class TwoFactorSignInHelper(
//        private val serverProperties: OAuth2ServerProperties,
//        private val tokenStore: TokenStore,
//        private val eventPublisher: ApplicationEventPublisher,
//        private val clientDetailsService: ClientDetailsService,
//        private val oauth2RequestFactory: OAuth2RequestFactory,
//        private val tokenServices: AuthorizationServerTokenServices
//) {
//
//    init {
//        (tokenServices as? DefaultTokenServices)?.apply {
//            this.setAccessTokenValiditySeconds(
//                    1.coerceAtLeast(serverProperties.token.accessTokenExpiration.seconds.toInt())
//            )
//            this.setRefreshTokenValiditySeconds(
//                    1.coerceAtLeast(serverProperties.token.refreshTokenExpiration.seconds.toInt())
//            )
//        }
//
//    }
//
//    fun signIn(
//            clientId: String,
//            user: ITwoFactorUserDetails,
//            twoFactorGranted: Boolean = false,
//            scopes: Set<String> = setOf()
//    ): OAuth2AccessToken {
//        if (!user.isTwoFactorEnabled() && twoFactorGranted) {
//            throw IllegalArgumentException("SignIn user isTwoFactorEnabled = false, but twoFactorGranted be set to true.");
//        }
//        return signIn(
//                clientId,
//                user.getUserId(),
//                user.username,
//                twoFactorGranted,
//                user.isTwoFactorEnabled(),
//                user.authorities,
//                scopes,
//                user.getTokenAttributes()
//        )
//    }
//
//    fun signIn(
//            clientId: String,
//            userId: String,
//            userName: String,
//            twoFactorGranted: Boolean = false,
//            twoFactorEnabled: Boolean = false,
//            authorities: Iterable<GrantedAuthority> = setOf(),
//            scope: Set<String> = setOf(),
//            attachedFields: Map<String, String> = mapOf()
//    ): OAuth2AccessToken {
//        return signIn(
//                clientId,
//                userId,
//                userName,
//                authorities.map { it.authority },
//                if (twoFactorEnabled) twoFactorGranted else null,
//                scope,
//                attachedFields
//        )
//    }
//
//    fun signIn(
//            clientId: String,
//            userId: String,
//            userName: String,
//            authorities: Iterable<String>,
//            twoFactorGranted: Boolean? = null,
//            scope: Set<String> = setOf(),
//            attachedFields: Map<String, String> = mapOf()
//    ): OAuth2AccessToken {
//
//        val authorityObjects = ArrayList(authorities.map { SimpleGrantedAuthority(it) })
//        val client = clientDetailsService.loadClientByClientId(clientId)
//        val user = SimpleTwoFactorUserDetails(
//                userId, userName,
//                twoFactorEnabled = twoFactorGranted != null,
//                authorities = authorityObjects,
//                attachedFields = attachedFields
//        )
//
//        val request = AuthorizationRequest(clientId, scope).apply {
//            this.authorities = authorityObjects
//        }
//
//        val tokenRequest = oauth2RequestFactory.createTokenRequest(request, Constants.GRANT_TYPE_PASSWORD)
//        val oauth2Request = oauth2RequestFactory.createOAuth2Request(client, tokenRequest)
//
//        val userAuthentication = UsernamePasswordAuthenticationToken(user, "", authorityObjects)
//                .apply {
//                    val map = mutableMapOf<String, Any>()
//                    TwoFactorAuthenticationConverter.setUserDetails(map, user, twoFactorGranted)
//
//                    this.details = map
//                }
//
//        val authentication = OAuth2Authentication(oauth2Request, userAuthentication).apply {
//            this.isAuthenticated = true
//        }
//
//        val token = tokenServices.createAccessToken(authentication)
//        this.eventPublisher.publishEvent(UserSignedInEvent(this, authentication))
//        return token
//    }
//
//    fun signInTwoFactor(): OAuth2AccessToken {
//        return signInTwoFactorCore(SecurityContextHolder.getContext().authentication)
//    }
//
////    fun signInTwoFactorAsync(): Mono<OAuth2AccessToken> {
////        return ReactiveSecurityContextHolder.getContext().map {
////            val auth = SecurityContextHolder.getContext().authentication as? OAuth2Authentication
////            val token = signInTwoFactorCore(auth)
////            token
////        }
////    }
//
//
//    private fun signInTwoFactorCore(auth: Authentication?): OAuth2AccessToken {
//        if (auth == null || !auth.isAuthenticated) {
//            throw BadCredentialsException("Current authentication is not authenticated.")
//        }
//
//        val oauth2Auth = if (auth is OAuth2Authentication) {
//            auth
//        } else {
//            val token = OAuth2Utils.getTokenValue(auth)
//
//            if (token.isNullOrBlank()) {
//                throw BadCredentialsException("bad oauth2 authentication, token value not existed.")
//            }
//
//            tokenStore.readAuthentication(token)
//                    ?: throw BadCredentialsException("Current authentication is not authenticated.")
//        }
//
//        val details = oauth2Auth.userAuthentication?.details as? Map<*, *>
//        var userId = (details?.getOrDefault(Constants.CLAIM_USER_ID, "")?.toString()).orEmpty()
//
//        if (userId.isBlank()) {
//            userId = OAuth2Utils.getTwoFactorPrincipal(auth).userId
//        }
//
//        val userName = oauth2Auth.userAuthentication.name
//        val clientId = oauth2Auth.oAuth2Request.clientId
//        val scope = oauth2Auth.oAuth2Request.scope
//        this.signOut()
//        return signIn(clientId, userId, userName, true, true, oauth2Auth.authorities, scope, details?.getAccessTokenAttachedFields() ?: mapOf())
//    }
//
//    private fun OAuth2AccessToken.getAttachedFields(): Map<String, String> {
//        return this.additionalInformation.filter {
//            !isWellKnownClaim(it.key)
//        }.map {
//            it.key to it.value.toString()
//        }.toMap()
//    }
//
//    private val knownFields = mutableSetOf<String>(
//            Constants.CLAIM_TWO_FACTOR,
//            Constants.CLAIM_USER_ID,
//            Constants.CLAIM_AUTHORITIES,
//            Constants.CLAIM_USER_NAME,
//            Constants.CLAIM_EXP,
//            Constants.CLAIM_AUD,
//            Constants.CLAIM_IAT,
//            Constants.CLAIM_ISS,
//            Constants.CLAIM_JTI,
//            Constants.CLAIM_NBF,
//            Constants.CLAIM_SUB,
//            OAuth2AccessToken.ACCESS_TOKEN,
//            OAuth2AccessToken.BEARER_TYPE,
//            OAuth2AccessToken.EXPIRES_IN,
//            OAuth2AccessToken.OAUTH2_TYPE,
//            OAuth2AccessToken.REFRESH_TOKEN,
//            OAuth2AccessToken.SCOPE,
//            "client_id",
//            "grant_type"
//    )
//
//    private fun Map<*, *>.getAccessTokenAttachedFields(): Map<String, String> {
//        return this.filter {
//            it.key.toString() !in knownFields
//        }.map {
//            it.key.toString() to it.value.toString()
//        }.toMap()
//    }
//
//
//
//    fun signOut() {
//        val auth = SecurityContextHolder.getContext().authentication
//        if (auth != null) {
//            val tokenValue = OAuth2Utils.getTokenValue(auth)
//            if (tokenValue != null) {
//                (tokenServices as? DefaultTokenServices)?.revokeToken(tokenValue)
//            }
//        }
//    }
//}