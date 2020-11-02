package com.labijie.infra.oauth2.testing

import com.labijie.infra.oauth2.TwoFactorSignInHelper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/test")
class TestController {
    @Autowired
    private lateinit var signInHelper : TwoFactorSignInHelper

    @PostMapping("/signin-2f")
    fun twoFacSignIn(): OAuth2AccessToken {
        return signInHelper.signInTwoFactor()
    }

    @GetMapping("/2fac")
    fun twrFacAction(): String {
        return "ok"
    }

    @GetMapping("/1fac")
    fun oneFacAction(): String{
        return "ok"
    }
}