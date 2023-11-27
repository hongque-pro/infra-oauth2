package com.labijie.infra.oauth2

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext

class TwoFactorJwtCustomizer : IJwtCustomizer {
    override fun customizeToken(context: JwtEncodingContext) {
        val au = context.getPrincipal<Authentication>()
        val details = au.principal as? ITwoFactorUserDetails
        if(details != null){
           details.getTokenAttributes().forEach { (t, u) ->
               context.claims.claim(t, u)
           }
           if(details.isTwoFactorEnabled()){
               val granted = context.get<Boolean>(OAuth2Constants.CLAIM_TWO_FACTOR)
               context.claims.claim(OAuth2Constants.CLAIM_TWO_FACTOR, granted)
           }
            context.claims.claim(OAuth2Constants.CLAIM_USER_ID, details.getUserId())
            context.claims.claim(OAuth2Constants.CLAIM_USER_NAME, details.username)
            context.claims.claim(OAuth2Constants.CLAIM_AUTHORITIES, details.authorities.map { it.authority })
        }
    }
}