package com.labijie.infra.oauth2.customizer

import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.OAuth2Constants
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext

class TwoFactorJwtCustomizer : IJwtCustomizer {
    override fun customizeToken(context: JwtEncodingContext) {
        if(context.tokenType == OAuth2TokenType.ACCESS_TOKEN) {
            val au = context.getPrincipal<Authentication>()
            val details = au.principal as? ITwoFactorUserDetails
            if (details != null) {
                details.getTokenAttributes().forEach { (t, u) ->
                    context.claims.claim(t, u)
                }
                if (details.isTwoFactorEnabled() && au is TwoFactorGrantedAuthentication) {
                    context.claims.claim(OAuth2Constants.CLAIM_TWO_FACTOR, true)
                }
                context.claims.claim(OAuth2Constants.CLAIM_USER_ID, details.getUserId())
                context.claims.claim(OAuth2Constants.CLAIM_USER_NAME, details.username)
                context.claims.claim(OAuth2Constants.CLAIM_AUTHORITIES, details.authorities.map { it.authority })
            }
        }
    }
}