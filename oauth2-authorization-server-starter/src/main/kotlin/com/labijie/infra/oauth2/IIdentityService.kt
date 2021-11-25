package com.labijie.infra.oauth2

import org.springframework.security.authentication.InternalAuthenticationServiceException
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
interface IIdentityService {

    val customPasswordChecks: Boolean
        get() = false

    @Throws(UsernameNotFoundException::class, InternalAuthenticationServiceException::class)
    fun getUserByName(userName: String): ITwoFactorUserDetails

    fun authenticationChecks(authenticationCheckingContext: AuthenticationCheckingContext): SignInResult
}