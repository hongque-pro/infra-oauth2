package com.labijie.dummy

import com.labijie.infra.oauth2.AuthorizationPlainObject
import org.springframework.boot.CommandLineRunner

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/30
 *
 */
class ApplicationRunner : CommandLineRunner {
    override fun run(vararg args: String?) {
        val obj = AuthorizationPlainObject()
    }
}