package com.labijie.infra.oauth2

import org.springframework.security.oauth2.server.authorization.JwtEncodingContext


interface IJwtCustomizer {
    fun customizeToken(context: JwtEncodingContext)
}