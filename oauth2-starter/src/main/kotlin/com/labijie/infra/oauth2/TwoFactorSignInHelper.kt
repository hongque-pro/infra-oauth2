package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.events.UserSignedInEvent
import com.labijie.infra.oauth2.token.TwoFactorAuthenticationConverter
import com.labijie.infra.utils.logger
import org.springframework.context.ApplicationEventPublisher
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices
import org.springframework.security.oauth2.provider.token.DefaultTokenServices

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class TwoFactorSignInHelper(
        private val eventPublisher: ApplicationEventPublisher,
        private val clientDetailsService: ClientDetailsService,
        private val oauth2RequestFactory: OAuth2RequestFactory,
        private val tokenServices: AuthorizationServerTokenServices) {

    fun signIn(clientId: String, user: ITwoFactorUserDetails, twoFactorGranted: Boolean = false, scopes: Set<String> = setOf()): OAuth2AccessToken {
        if (!user.isTwoFactorEnabled() && twoFactorGranted) {
            throw IllegalArgumentException("SignIn user isTwoFactorEnabled = false, but twoFactorGranted be set to true.");
        }
        return signIn(
                clientId,
                user.getUserId(),
                user.username,
                twoFactorGranted,
                user.isTwoFactorEnabled(),
                user.authorities,
                scopes,
                user.getAttachedTokenFields())
    }

    fun signIn(clientId: String,
               userId: String,
               userName: String,
               twoFactorGranted: Boolean = false,
               twoFactorEnabled: Boolean = false,
               authorities: Iterable<GrantedAuthority> = setOf(),
               scope: Set<String> = setOf(),
               attachedFields: Map<String, String> = mapOf()): OAuth2AccessToken {
        return signIn(clientId,
                userId,
                userName,
                authorities.map { it.authority },
                if (twoFactorEnabled) twoFactorGranted else null,
                scope,
                attachedFields)
    }

    fun signIn(clientId: String,
               userId: String,
               userName: String,
               authorities: Iterable<String>,
               twoFactorGranted: Boolean? = null,
               scope: Set<String> = setOf(),
               attachedFields: Map<String, String> = mapOf()): OAuth2AccessToken {

        val authorityObjects = ArrayList(authorities.map { GrantedAuthorityObject(it) })
        val client = clientDetailsService.loadClientByClientId(clientId)
        val user = SimpleTwoFactorUserDetails(
                userId, userName,
                twoFactorEnabled = twoFactorGranted != null,
                authorities = authorityObjects,
                attachedFields = attachedFields)

        val request = AuthorizationRequest(clientId, scope).apply {
            this.authorities = authorityObjects
        }

        val tokenRequest = oauth2RequestFactory.createTokenRequest(request, Constants.GRANT_TYPE_PASSWORD)
        val oauth2Request = oauth2RequestFactory.createOAuth2Request(client, tokenRequest)

        val userAuthentication = UsernamePasswordAuthenticationToken(user, "", authorityObjects)
                .apply {
                    val map = mutableMapOf<String, Any>()
                    TwoFactorAuthenticationConverter.setUserDetails(map, user)

                    this.details = map
                }

        val authentication = OAuth2Authentication(oauth2Request, userAuthentication).apply {
            this.isAuthenticated = true
        }

        this.eventPublisher.publishEvent(UserSignedInEvent(this, authentication))
        return tokenServices.createAccessToken(authentication)
    }

    fun signInTwoFactor(): OAuth2AccessToken {
        val auth = SecurityContextHolder.getContext().authentication as? OAuth2Authentication
        return signInTwoFactorCore(auth)
    }

//    fun signInTwoFactorAsync(): Mono<OAuth2AccessToken> {
//        return ReactiveSecurityContextHolder.getContext().map {
//            val auth = SecurityContextHolder.getContext().authentication as? OAuth2Authentication
//            val token = signInTwoFactorCore(auth)
//            token
//        }
//    }


    private fun signInTwoFactorCore(auth: OAuth2Authentication?): OAuth2AccessToken {
        if (auth == null) {
            throw BadCredentialsException("Current authentication is not authenticated.")
        }
        val principal = auth.twoFactorPrincipal
        if (auth.isAuthenticated) {
            val userName = auth.userAuthentication.name
            val clientId = auth.oAuth2Request.clientId
            val scope = auth.oAuth2Request.scope
            val userId = principal.userId
            this.signOut()
            return signIn(clientId, userId, userName, true, true, auth.authorities, scope)
        } else {
            throw BadCredentialsException("bad oauth2 authentication.")
        }
    }

    private fun signOut(auth: OAuth2Authentication?) {
        if (auth != null) {
            val detail = (auth.details as? OAuth2AuthenticationDetails)
            if (detail != null) {
                val service = this.tokenServices as? DefaultTokenServices
                service?.revokeToken(detail.tokenValue)
            }
        } else {
            logger.warn("Current token was not an oauth2 authentication token, Sign out was unsupported.")
        }
    }

    fun signOut() {
        val auth = (SecurityContextHolder.getContext().authentication as? OAuth2Authentication)
        this.signOut(auth)
    }
}