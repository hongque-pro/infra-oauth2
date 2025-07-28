package com.labijie.infra.oauth2

import org.springframework.security.config.annotation.web.builders.HttpSecurity

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/26
 *
 */
interface IResourceServerHttpSecurityConfigurer {
    fun configure(http: HttpSecurity): Unit
}