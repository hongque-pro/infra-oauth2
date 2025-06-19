package com.labijie.dummy.auth

import com.labijie.infra.oauth2.configuration.DefaultClientProperties

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/19
 *
 */
object DummyConstants {
    const val username = "testUser"
    const val userPassword = "pass0rd"
    val clientId by lazy {
        DefaultClientProperties().clientId
    }
    val clientSecret by lazy {
        DefaultClientProperties().secret
    }
    const val resourceId = "test-resources"
    const val scope = "test-scope"
}