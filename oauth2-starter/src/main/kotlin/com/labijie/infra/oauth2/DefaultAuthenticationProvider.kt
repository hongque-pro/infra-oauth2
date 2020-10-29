package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.Constants.TOKEN_ATTACHED_FIELD_PREFIX
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.core.Ordered
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.password.PasswordEncoder

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class DefaultAuthenticationProvider(svc: DefaultUserService, passwordEncoder: PasswordEncoder) :
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
        attachedFields.forEach { (k, v) -> map["$TOKEN_ATTACHED_FIELD_PREFIX$k"] = v  }

        map[Constants.USER_TWO_FACTOR_PROPERTY] = granted
        map[Constants.USER_ID_PROPERTY] = user.getUserId()

        authentication.details = map
    }

}