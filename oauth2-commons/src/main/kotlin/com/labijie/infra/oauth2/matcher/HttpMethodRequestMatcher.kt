package com.labijie.infra.oauth2.matcher

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpMethod
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/31
 *
 */
class HttpMethodRequestMatcher : RequestMatcher {

    private val methods: Set<String>

    constructor(vararg method: HttpMethod) {
        this.methods = method.map { it.name().lowercase() }.toSet()
    }

    constructor(methods: Collection<HttpMethod>) {
        this.methods = methods.map { it.name().lowercase() }.toSet()
    }


    override fun matches(request: HttpServletRequest): Boolean {
        return methods.contains(request.method.lowercase())
    }
}