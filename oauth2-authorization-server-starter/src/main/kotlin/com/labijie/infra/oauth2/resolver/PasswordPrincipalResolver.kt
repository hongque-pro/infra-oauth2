package com.labijie.infra.oauth2.resolver

import com.labijie.infra.oauth2.IPrincipalResolver
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.OAuth2ServerUtils.toPrincipal
import com.labijie.infra.oauth2.TwoFactorPrincipal
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

        return user.toPrincipal()
    }
}