/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2.mvc

import com.labijie.infra.oauth2.OAuth2ExceptionHandler
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.access.AccessDeniedException
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/oauth2")
class OAuth2ServerCommonsController: ApplicationContextAware {
    private lateinit var applicationContext: ApplicationContext


    @GetMapping("/unauthorized")
    fun default(httpServletRequest: HttpServletRequest, httpServletResponse: HttpServletResponse) {
        OAuth2ExceptionHandler.handle(httpServletRequest, httpServletResponse, AccessDeniedException("Authorization is required to access the resource."))
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }
}