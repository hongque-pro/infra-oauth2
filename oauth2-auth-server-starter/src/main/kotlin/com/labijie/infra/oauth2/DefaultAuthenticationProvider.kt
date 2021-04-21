package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.events.UserSignedInEvent
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationEventPublisher
import org.springframework.core.Ordered
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.password.PasswordEncoder

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class DefaultAuthenticationProvider(private val eventPublisher: ApplicationEventPublisher, svc: DefaultUserService, passwordEncoder: PasswordEncoder) :
        DaoAuthenticationProvider(), Ordered {
    companion object {
        val slf4jLogger = LoggerFactory.getLogger(DefaultAuthenticationProvider::class.java)!!
    }

    override fun getOrder(): Int {
        return -1
    }

    init {
        this.userDetailsService = svc
        this.passwordEncoder = passwordEncoder
    }

//
//    override fun setPasswordEncoder(passwordEncoder: PasswordEncoder?) {
////        super.setPasswordEncoder(passwordEncoder)
//    }

    override fun additionalAuthenticationChecks(userDetails: UserDetails, authentication: UsernamePasswordAuthenticationToken) {

        val userSvc = userDetailsService as DefaultUserService
        if (!userSvc.customPasswordChecks) {
            super.additionalAuthenticationChecks(userDetails, authentication)
        }

        val twoFactorUserDetails = userDetails as ITwoFactorUserDetails

        val context = AuthenticationCheckingContext(
            twoFactorUserDetails,
            authentication,
            this.passwordEncoder!!
        )

        @Suppress("UNCHECKED_CAST")
        val result = userSvc.additionalAuthenticationChecks(context)
        when (result.type) {
            SignInResultType.Failed -> {
                throw BadCredentialsException(result.errorCode)
            }

            SignInResultType.Success -> {
                setTwoFactorGranted(authentication, twoFactorUserDetails, true)
            }
            SignInResultType.TwoFactorRequired -> {
                if (!twoFactorUserDetails.isTwoFactorEnabled()) {
                    slf4jLogger.warn("Got SignInResultType.TwoFactorRequired as the result of IIdentityService.authenticationChecks method, but two factor disabled on user details.")
                }
                setTwoFactorGranted(authentication, twoFactorUserDetails, false)
            }
        }
    }

    private fun setTwoFactorGranted(authentication: UsernamePasswordAuthenticationToken, user: ITwoFactorUserDetails, granted: Boolean) {
        @Suppress("UNCHECKED_CAST")
        val map = (authentication.details as? MutableMap<String, Any>) ?: mutableMapOf()

        val attachedFields = user.getAttachedTokenFields()
        attachedFields.forEach { (k, v) -> map[k] = v  }

        map[Constants.CLAIM_TWO_FACTOR] = granted
        map[Constants.CLAIM_USER_ID] = user.getUserId()

        authentication.details = map
    }


    override fun createSuccessAuthentication(principal: Any?, authentication: Authentication?, user: UserDetails?): Authentication {
        val r = super.createSuccessAuthentication(principal, authentication, user)
        val event = UserSignedInEvent(this, r)
        this.eventPublisher.publishEvent(event)
        return r
    }
}