/**
 * @author Anders Xiao
 * @date 2024-07-25
 */
package com.labijie.infra.oauth2.resource.component

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authorization.SingleResultAuthorizationManager
import org.springframework.security.config.ObjectPostProcessor
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcherEntry


object RequestMatcherPostProcessor : ObjectPostProcessor<RequestMatcherDelegatingAuthorizationManager> {

    private var foundMatchers: List<RequestMatcher> = listOf()


    @Suppress("unused")
    val publicMatchers = foundMatchers

    fun isPermitAll(request: HttpServletRequest): Boolean {
        if(foundMatchers.isEmpty()) {
            return false
        }
        return foundMatchers.any { it.matcher(request).isMatch }
    }

    override fun <T : RequestMatcherDelegatingAuthorizationManager> postProcess(manager: T): T {
        val mappings = manager::class.java.getDeclaredField("mappings").let {
            it.isAccessible = true
            it.get(manager)
        }
        if (mappings is List<*>) {
            foundMatchers = mappings.filterIsInstance<RequestMatcherEntry<*>>()
                .filter {
                    it.entry == SingleResultAuthorizationManager.permitAll<T>()
                }.map { it.requestMatcher }

        }

        return manager
    }
}