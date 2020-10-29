package com.labijie.infra.oauth2.preauth

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-17
 */
class TwoFactorPreAuthenticationProvider : PreAuthenticatedAuthenticationProvider() {

    override fun authenticate(authentication: Authentication): Authentication {
        val auth = super.authenticate(authentication) as PreAuthenticatedAuthenticationToken
        val userAuthentication = authentication.principal as? Authentication
        if (userAuthentication != null) {
            auth.details = userAuthentication.details
        }
        //override new user name
        val user = (auth.principal as? UserDetails)
        val map = (auth.details as? Map<*, *>)?.toMutableMap() ?: mutableMapOf()

        if (user != null) {
            map[UserAuthenticationConverter.USERNAME] = user.username!!
        }
        val tUser = user as? ITwoFactorUserDetails
        if (tUser != null) {
            map[Constants.USER_ID_PROPERTY] = tUser.getUserId()
        }
        auth.details = map
        return auth
    }
}