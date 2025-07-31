package com.labijie.infra.oauth2.matcher

import com.labijie.infra.oauth2.buildMatchers
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/31
 *
 */
class ControllerClassRequestMatcher(
    private val requestMappingHandlerMapping: RequestMappingHandlerMapping,
    vararg controllerClass: Class<*>
) : RequestMatcher {

    private val controllerClasses = controllerClass.toSet()

    private fun getUrlsFromController(mapping: RequestMappingHandlerMapping): Collection<RequestMatcher> {
        val mappings = mapping.handlerMethods ?: mapOf()
        val infos = mappings
            .filter { (_, method) ->
                controllerClasses.contains(method.beanType)
            }
            .map { (info, _) -> info }

        val matchers = mutableListOf<RequestMatcher>()
        infos.forEach { info ->
            info.pathPatternsCondition?.patterns?.let { patterns ->
                val list = info.buildMatchers()
                matchers.addAll(list)
            }
        }
        return matchers
    }

    private val pathMatchers by lazy {
        getUrlsFromController(requestMappingHandlerMapping)
    }

    override fun matches(request: HttpServletRequest): Boolean {
        return pathMatchers.any {
            val matched = it.matches(request)
            matched
        }
    }
}