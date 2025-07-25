package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.oauth2.events.UserSignedInEvent
import org.junit.jupiter.api.Assertions
import org.springframework.context.ApplicationListener

class OAuth2SignInTestingListener : ApplicationListener<UserSignedInEvent> {
    override fun onApplicationEvent(event: UserSignedInEvent) {
        val principal = event.principle
        Assertions.assertEquals(OAuth2TestingUtils.TestUserName, principal.userName)
    }
}