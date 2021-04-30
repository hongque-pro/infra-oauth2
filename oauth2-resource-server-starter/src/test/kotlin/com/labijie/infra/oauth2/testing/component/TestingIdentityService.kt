package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.oauth2.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class TestingIdentityService: IIdentityService {

    companion object {

    }

    override fun getUserByName(userName: String): ITwoFactorUserDetails {
        return SimpleTwoFactorUserDetails.fromUserDetails(OAuth2TestingUtils.TestUser)
    }

    override fun authenticationChecks(authenticationCheckingContext: AuthenticationCheckingContext): SignInResult {
        return SignInResult(type = SignInResultType.TwoFactorRequired, user = authenticationCheckingContext.userDetails)
    }
}