/**
 * @author Anders Xiao
 * @date 2023-12-29
 */
package com.labijie.infra.oauth2.customizer

import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.OAuth2Constants
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import java.security.Principal


class InfraClaimsContextCustomizer : OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
    override fun customize(context: OAuth2TokenClaimsContext) {
        if(context.authorizationGrantType == AuthorizationGrantType.REFRESH_TOKEN
        ){
            val au = context.getPrincipal<Authentication>()
            val principal = context.authorization?.getAttribute<Any>(Principal::class.java.name)
            val details = principal as? ITwoFactorUserDetails
            details?.run {
                details.getTokenAttributes().forEach { (t, u) ->
                    context.claims.claim(t, u)
                }
                if(details.isTwoFactorEnabled() && au is TwoFactorGrantedAuthentication){
                    context.claims.claim(OAuth2Constants.CLAIM_TWO_FACTOR, true)
                }
                context.claims.claim(OAuth2Constants.CLAIM_USER_ID, details.getUserId())
                context.claims.claim(OAuth2Constants.CLAIM_USER_NAME, details.username)
                context.claims.claim(OAuth2Constants.CLAIM_AUTHORITIES, details.authorities.map { it.authority })
            }
        }
    }
}