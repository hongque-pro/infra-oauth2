package com.labijie.infra.oauth2.testing.component

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

object OAuth2TestingUtils {
        val passwordEncoder = BCryptPasswordEncoder()
}