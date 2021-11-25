package com.labijie.infra.oauth2

import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

class NoopPasswordEncoder : PasswordEncoder {
    companion object{
        val INSTANCE: PasswordEncoder = NoopPasswordEncoder()
    }

    private fun NoOpPasswordEncoder() {}

    override fun encode(rawPassword: CharSequence): String? {
        return rawPassword.toString()
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean {
        return rawPassword.toString() == encodedPassword
    }

}