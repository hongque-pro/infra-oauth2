package com.labijie.infra.oauth2.resolver

import com.labijie.infra.oauth2.*
import org.springframework.security.core.Authentication

class SignInPrincipalResolver : IPrincipalResolver {
    override fun support(authentication: Authentication): Boolean {
       return authentication.principal is ITwoFactorUserDetails
    }

    override fun resolvePrincipal(authentication: Authentication): TwoFactorPrincipal {
        val user = authentication.principal as ITwoFactorUserDetails

        return TwoFactorPrincipal(
            user.getUserId(),
            user.username,
            user.getTokenAttributes().getOrDefault(Constants.CLAIM_TWO_FACTOR, "false").toBoolean(),
            user.authorities.toMutableList(),
            user.getTokenAttributes().filter { !isWellKnownClaim(it.key) }
        )
    }
}