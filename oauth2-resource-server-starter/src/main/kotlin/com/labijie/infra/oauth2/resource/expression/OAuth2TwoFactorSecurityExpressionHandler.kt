package com.labijie.infra.oauth2.resource.expression

import com.labijie.infra.oauth2.Constants
import org.springframework.context.ApplicationContext
import org.springframework.security.access.PermissionEvaluator
import org.springframework.security.access.expression.SecurityExpressionOperations
import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.core.GrantedAuthorityDefaults
import org.springframework.security.core.Authentication
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-24
 */
class OAuth2TwoFactorSecurityExpressionHandler(http : HttpSecurity) : DefaultWebSecurityExpressionHandler() {

    private var resolver: AuthenticationTrustResolver = AuthenticationTrustResolverImpl()

    init {
        val trustResolver: AuthenticationTrustResolver? = http.getSharedObject(AuthenticationTrustResolver::class.java)
        if (trustResolver != null) {
            this.setTrustResolver(trustResolver)
        }
        val context: ApplicationContext? = http.getSharedObject(ApplicationContext::class.java)
        if (context != null) {
            val roleHiearchyBeanNames = context.getBeanNamesForType(RoleHierarchy::class.java)
            if (roleHiearchyBeanNames.size == 1) {
                this.roleHierarchy = context.getBean(roleHiearchyBeanNames[0], RoleHierarchy::class.java)
            }
            val grantedAuthorityDefaultsBeanNames = context.getBeanNamesForType(GrantedAuthorityDefaults::class.java)
            if (grantedAuthorityDefaultsBeanNames.size == 1) {
                val grantedAuthorityDefaults = context
                        .getBean(grantedAuthorityDefaultsBeanNames[0], GrantedAuthorityDefaults::class.java)
                this.setDefaultRolePrefix(grantedAuthorityDefaults.rolePrefix)
            }
            val permissionEvaluatorBeanNames = context.getBeanNamesForType(PermissionEvaluator::class.java)
            if (permissionEvaluatorBeanNames.size == 1) {
                val permissionEvaluator = context.getBean(permissionEvaluatorBeanNames[0],
                        PermissionEvaluator::class.java)
                this.permissionEvaluator = permissionEvaluator
            }
        }
    }


    override fun createSecurityExpressionRoot(authentication: Authentication?, fi: FilterInvocation?): SecurityExpressionOperations {
        val root = OAuth2TwoFactorExpressionRoot(authentication, fi)
        root.setPermissionEvaluator(permissionEvaluator)
        root.setTrustResolver(resolver)
        root.setRoleHierarchy(roleHierarchy)
        root.setDefaultRolePrefix(Constants.ROLE_AUTHORITY_PREFIX)

        return root
    }

}