package com.labijie.infra.oauth2.resolver

import com.labijie.infra.oauth2.*
import org.springframework.security.core.Authentication

class PasswordPrincipalResolver : IPrincipalResolver {
    override fun support(authentication: Authentication): Boolean {
       return authentication.isAuthenticated && findPrinciple(authentication) != null
    }

    private fun findPrinciple(authentication: Authentication): ITwoFactorUserDetails? {
        if(authentication.principal is ITwoFactorUserDetails){
            return authentication.principal as ITwoFactorUserDetails
        }
        if(authentication.principal is Authentication){
            return findPrinciple(authentication.principal as Authentication)
        }
        return null
    }

    override fun resolvePrincipal(authentication: Authentication): TwoFactorPrincipal {
        val user = findPrinciple(authentication)  as ITwoFactorUserDetails

        return TwoFactorPrincipal(
            user.getUserId(),
            user.username,
            user.getTokenAttributes().getOrDefault(OAuth2Constants.CLAIM_TWO_FACTOR, "false").toBoolean(),
            user.authorities.toMutableList(),
            user.getTokenAttributes().filter { !isWellKnownClaim(it.key) }
        )
    }
}