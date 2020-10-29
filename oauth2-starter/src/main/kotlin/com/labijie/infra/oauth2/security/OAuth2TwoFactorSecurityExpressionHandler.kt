package com.labijie.infra.oauth2.security

import org.springframework.security.access.expression.SecurityExpressionOperations
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler
import org.springframework.security.web.FilterInvocation

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-24
 */
object OAuth2TwoFactorSecurityExpressionHandler : OAuth2WebSecurityExpressionHandler() {

    private var resolver: AuthenticationTrustResolver = AuthenticationTrustResolverImpl()
    private var rolePrefix = "ROLE_"

    override fun createSecurityExpressionRoot(
            authentication: Authentication, fi: FilterInvocation): SecurityExpressionOperations {
        val root = OAuth2TwoFactorExpressionRoot(authentication, fi)
        root.setPermissionEvaluator(permissionEvaluator)
        root.setTrustResolver(resolver)
        root.setRoleHierarchy(roleHierarchy)
        root.setDefaultRolePrefix(rolePrefix)
        return root
    }
}