package com.labijie.infra.oauth2

import org.springframework.core.Ordered
import org.springframework.security.core.Authentication

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 18:52
 * @Description:
 */
interface IPrincipalResolver : Ordered {
    override fun getOrder(): Int = 0
    fun support(authentication: Authentication): Boolean
    fun resolvePrincipal(authentication: Authentication): TwoFactorPrincipal
}