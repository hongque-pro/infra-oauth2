package com.labijie.infra.oauth2.resource.expression

import org.springframework.expression.EvaluationContext
import org.springframework.expression.spel.support.StandardEvaluationContext
import org.springframework.security.access.expression.SecurityExpressionOperations
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import java.util.function.Supplier

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-24
 */
class OAuth2TwoFactorSecurityExpressionHandler : DefaultHttpSecurityExpressionHandler() {

    private val r = AuthenticationTrustResolverImpl()
    private val defaultRolePrefix = "ROLE_"

    init {
        setTrustResolver(r)
    }

    override fun createSecurityExpressionRoot(
        authentication: Authentication,
        context: RequestAuthorizationContext
    ): SecurityExpressionOperations {
        return createSecurityExpressionRoot({ authentication }, context)
    }

    override fun createEvaluationContext(
        authentication: Supplier<Authentication>,
        context: RequestAuthorizationContext
    ): EvaluationContext {
        val root = createSecurityExpressionRoot(authentication, context)
        val ctx = StandardEvaluationContext(root)
        ctx.beanResolver = this.beanResolver
        context.variables.forEach { (name: String?, value: String?) ->
            ctx.setVariable(
                name,
                value
            )
        }
        return ctx
    }

    fun createSecurityExpressionRoot(
        authentication: Supplier<Authentication>,
        context: RequestAuthorizationContext
    ): OAuth2TwoFactorExpressionRoot {
        val root = OAuth2TwoFactorExpressionRoot(authentication, context.request)
        root.setRoleHierarchy(roleHierarchy)
        root.setPermissionEvaluator(permissionEvaluator)
        root.setTrustResolver(r)
        root.setDefaultRolePrefix(defaultRolePrefix)
        return root
    }

}