package com.labijie.infra.oauth2

import org.springframework.security.core.userdetails.UserDetails

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
data class SignInResult constructor(
        val type: SignInResultType = SignInResultType.Failed,
        val user: UserDetails? = null,
        val errorCode: String? = null,
        val errorDescription: String? = null)