/**
 * @author Anders Xiao
 * @date 2024-07-25
 */
package com.labijie.infra.oauth2.resource.component

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcherEntry


object RequestMatcherPostProcessor : ObjectPostProcessor<RequestMatcherDelegatingAuthorizationManager> {

    private val permitAllAuthorizationManager = getPermitAllAuthorizationManager()

    private var foundMatchers: List<RequestMatcher> = listOf()


    private fun getPermitAllAuthorizationManager(): AuthorizationManager<RequestAuthorizationContext> {
        val field = AuthorizeHttpRequestsConfigurer::class.java.getDeclaredField("permitAllAuthorizationManager")
        field.isAccessible = true

        @Suppress("UNCHECKED_CAST")
        return field.get(null) as AuthorizationManager<RequestAuthorizationContext>
    }

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
                    it.entry == permitAllAuthorizationManager
                }.map { it.requestMatcher }

        }

        return manager
    }
}