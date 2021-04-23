package com.labijie.infra.oauth2.resource.resolver

import com.labijie.infra.oauth2.ITokenValueResolver
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken

class BearTokenValueResolver : ITokenValueResolver {
    override fun support(authentication: Authentication): Boolean {
        return authentication is AbstractOAuth2TokenAuthenticationToken<*>
    }

    override fun resolveToken(authentication: Authentication): String {
        val oauth2Token = authentication as AbstractOAuth2TokenAuthenticationToken<*>
        return oauth2Token.token.tokenValue
    }
}