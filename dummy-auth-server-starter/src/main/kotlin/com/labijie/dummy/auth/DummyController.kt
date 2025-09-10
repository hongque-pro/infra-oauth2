package com.labijie.dummy.auth

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2ServerUtils.toAccessToken
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.filter.ClientRequired
import jakarta.annotation.security.PermitAll
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/test")
class DummyController {
    @Autowired
    private lateinit var signInHelper: TwoFactorSignInHelper

    @PostMapping("/sign-2f")
    fun twoFacSignIn(): AccessToken {
        val token = signInHelper.signInTwoFactor().toAccessToken()
        return token
    }

    @ClientRequired
    @PostMapping("/fake-login/{username}")
    fun login(
        @PathVariable("username") username: String,
        client: RegisteredClient): AccessToken {
        val token = signInHelper.signIn(client.id, username).toAccessToken()
        return token
    }

    @GetMapping("/permitAll")
    fun permitAll(): String {
        return "ok"
    }

    @PermitAll
    @GetMapping("/permitAllAnno")
    fun permitAllAttribute(): String {
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