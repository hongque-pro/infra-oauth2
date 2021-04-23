package com.labijie.infra.oauth2

import org.springframework.beans.factory.ObjectProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import kotlin.jvm.Throws

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 19:34
 * @Description:
 */

fun copyAttributesTo(source: Map<String, Any>, key: String, destination: MutableMap<String, Any>) {
    val value = source.getOrDefault(key, "").toString()
    if (!value.isBlank()) {
        if (value == "true" || value == "false") {
            destination[key] = value.toBoolean()
        } else {
            destination[key] = value
        }
    }
}



