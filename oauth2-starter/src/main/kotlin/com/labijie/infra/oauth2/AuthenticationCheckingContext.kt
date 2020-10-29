package com.labijie.infra.oauth2

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-08
 */
data class AuthenticationCheckingContext(
    val userDetails: ITwoFactorUserDetails,
    val authentication: UsernamePasswordAuthenticationToken,
    val pwdEncoder: PasswordEncoder)