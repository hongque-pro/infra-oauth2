package com.labijie.infra.oauth2.resource.resolver

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.IPrincipalResolver
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.isWellKnownClaim
import com.labijie.infra.oauth2.resource.TwoFactorAuthenticatedPrincipal
import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorSecurityExpressionHandler
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 18:56
 * @Description:
 */
class BearTokenPrincipalResolver : IPrincipalResolver {
    override fun support(authentication: Authentication): Boolean {
        return authentication is AbstractOAuth2TokenAuthenticationToken<*>
    }

    override fun resolvePrincipal(authentication: Authentication): TwoFactorPrincipal {
        val token = authentication as AbstractOAuth2TokenAuthenticationToken<*>

        if (token.principal is TwoFactorAuthenticatedPrincipal) {
            val principal = token.principal as TwoFactorAuthenticatedPrincipal
            return principal.getTwoFactorPrincipal()
        }

        val attachments = mutableMapOf<String, String>()

        token.tokenAttributes.filter { kv ->
            kv.key != null &&
                    kv.value != null &&
                    kv.key is String &&
                    !isWellKnownClaim(kv.key.toString())
        }.forEach {
            attachments[it.key.toString()] = it.value.toString()
        }

        return TwoFactorPrincipal(
                token.tokenAttributes.getOrDefault(Constants.CLAIM_USER_ID, "").toString(),
                authentication.name ?: token.tokenAttributes.getOrDefault(Constants.CLAIM_USER_NAME, "").toString(),
                isTwoFactorGranted = token.tokenAttributes.getOrDefault(Constants.CLAIM_TWO_FACTOR, "false").toString().toBoolean(),
                authorities = token.authorities.filter {
                    it.authority.startsWith(Constants.ROLE_AUTHORITY_PREFIX)
                }.toMutableList(),
                attachedFields = attachments
        )
    }
}