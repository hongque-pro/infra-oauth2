package com.labijie.infra.oauth2

import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class DefaultUserService(private val identityService: IIdentityService) : UserDetailsService {

    val customPasswordChecks
        get() = identityService.customPasswordChecks


    override fun loadUserByUsername(username: String): UserDetails {
        return identityService.getUserByName(username)
    }

    fun additionalAuthenticationChecks(context: AuthenticationCheckingContext): SignInResult {
        return identityService.authenticationChecks(context)
    }
}