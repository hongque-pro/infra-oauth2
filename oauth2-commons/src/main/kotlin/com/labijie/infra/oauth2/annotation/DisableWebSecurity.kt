package com.labijie.infra.oauth2.annotation

import org.springframework.boot.autoconfigure.ImportAutoConfiguration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/26
 *
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS)
@ImportAutoConfiguration(NoSecurityAutoConfiguration::class)
annotation class DisableWebSecurity {
}