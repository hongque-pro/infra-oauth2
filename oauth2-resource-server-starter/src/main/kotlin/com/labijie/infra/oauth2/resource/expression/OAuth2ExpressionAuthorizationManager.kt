package com.labijie.infra.oauth2.resource.expression

import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.authorization.AuthorizationResult
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import java.util.function.Supplier

/**
 * @author Anders Xiao
 * @date 2023-11-27
 */
class OAuth2ExpressionAuthorizationManager(expression: String) : AuthorizationManager<RequestAuthorizationContext> {

    private val expressionAuthorizationManager: WebExpressionAuthorizationManager = WebExpressionAuthorizationManager(expression)

    init {
        expressionAuthorizationManager.setExpressionHandler(OAuth2TwoFactorSecurityExpressionHandler())
    }

    /**
     * Deprecated, please use authorize(Supplier, Object) instead
     */
    @Deprecated("Deprecated, please use authorize(Supplier, Object) instead")
    override fun check(
        authentication: Supplier<Authentication>?,
        context: RequestAuthorizationContext?
    ): AuthorizationDecision? {
        return expressionAuthorizationManager.check(authentication, context)
    }

    override fun authorize(
        authentication: Supplier<Authentication?>?,
        `object`: RequestAuthorizationContext?
    ): AuthorizationResult? {
        return expressionAuthorizationManager.authorize(authentication, `object`)
    }
}