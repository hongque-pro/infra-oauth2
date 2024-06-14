package com.labijie.infra.oauth2.testing

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2ServerUtils.toAccessToken
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/test")
class ResourceTestController {
    @Autowired
    private lateinit var signInHelper: TwoFactorSignInHelper
    
    @PostMapping("/sign-2f")
    fun twoFacSignIn(): AccessToken {
        val token = signInHelper.signInTwoFactor().toAccessToken()
        return token
    }

    @GetMapping("/permitAll")
    fun permitAll(): String {
        return "ok"
    }

    @GetMapping("/2fac")
    fun twrFacAction(): String {
        return "ok"
    }

    @GetMapping("/1fac")
    fun oneFacAction(): String {
        return "ok"
    }

    @PostMapping("/field-aaa-test")
    fun fieldAAA(): String {
        return "ok"
    }

    @PostMapping("/field-bbb-test")
    fun fieldBBB(): String {
        return "ok"
    }

    @PostMapping("/role-aa-test")
    fun roleAA(): String {
        return "ok"
    }

    @PostMapping("/role-bb-test")
    fun roleBB(): String {
        return "ok"
    }

    @GetMapping("/current-user")
    fun currentUser(): TwoFactorPrincipal {
        return OAuth2Utils.currentTwoFactorPrincipal()
    }
}