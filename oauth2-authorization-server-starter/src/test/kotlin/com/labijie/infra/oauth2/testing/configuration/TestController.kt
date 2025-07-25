package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2ServerUtils.toAccessToken
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController


@RestController
@RequestMapping
class TestController {

    @Autowired
    private lateinit var signInHelper: TwoFactorSignInHelper

    @RequestMapping("/fake-login")
    fun sign(): AccessToken {
        return signInHelper.signIn(OAuth2TestingUtils.TestClientId, OAuth2TestingUtils.TestUserName).toAccessToken()
    }


    @GetMapping("/access")
    fun access(): String {
        return "OK"
    }
}