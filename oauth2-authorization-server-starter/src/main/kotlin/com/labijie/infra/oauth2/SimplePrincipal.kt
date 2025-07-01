package com.labijie.infra.oauth2

import java.security.Principal

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/1
 *
 */

internal class SimplePrincipal(private val name: String) : Principal {
    override fun getName(): String? {
        return name
    }
}