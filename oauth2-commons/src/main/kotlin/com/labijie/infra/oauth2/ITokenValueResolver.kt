package com.labijie.infra.oauth2

import org.springframework.core.Ordered
import org.springframework.security.core.Authentication

interface ITokenValueResolver : Ordered {
    override fun getOrder(): Int = 0
    fun support(authentication: Authentication): Boolean
    fun resolveToken(authentication: Authentication): String
}