/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.OAuth2ExceptionHandler
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController


@RestController
@RequestMapping("/oauth2")
class UnauthorizedController {
    @GetMapping("/unauthorized")
    fun default(httpServletRequest: HttpServletRequest, httpServletResponse: HttpServletResponse) {
        OAuth2ExceptionHandler.INSTANCE.handle(httpServletRequest, httpServletResponse, AccessDeniedException("Authorization is required to access the resource."))
    }
}