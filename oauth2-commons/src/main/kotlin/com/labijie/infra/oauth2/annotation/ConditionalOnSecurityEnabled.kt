package com.labijie.infra.oauth2.annotation

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/26
 *
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@ConditionalOnMissingBean(NoSecurityMarker::class)
annotation class ConditionalOnSecurityEnabled