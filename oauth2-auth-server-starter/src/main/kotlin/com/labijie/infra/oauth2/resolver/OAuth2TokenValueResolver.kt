package com.labijie.infra.oauth2.resolver

import com.labijie.infra.oauth2.ITokenValueResolver
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.TokenStore

class OAuth2TokenValueResolver(private val tokenStore: TokenStore) : ITokenValueResolver {
    override fun support(authentication: Authentication): Boolean {
        return authentication.isAuthenticated && authentication is OAuth2Authentication
    }

    override fun resolveToken(authentication: Authentication): String {
        val t = authentication as OAuth2Authentication
        val token = tokenStore.getAccessToken(t)
        return token.value
    }
}