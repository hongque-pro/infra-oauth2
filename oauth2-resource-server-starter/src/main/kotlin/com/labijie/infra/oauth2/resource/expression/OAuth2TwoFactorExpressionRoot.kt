package com.labijie.infra.oauth2.resource.expression

import com.labijie.infra.oauth2.resource.getAttachedField
import com.labijie.infra.oauth2.resource.isTwoFactorGranted
import org.springframework.security.core.Authentication
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-24
 */
class OAuth2TwoFactorExpressionRoot(a: Authentication?, fi: FilterInvocation?)
    : WebSecurityExpressionRoot(a, fi) {

    fun twoFactorRequired() : Boolean {
        return this.authentication.isTwoFactorGranted
    }

    fun hasAttachedFieldValue(fieldName: String, value: String): Boolean {
        return this.authentication.getAttachedField(fieldName) == value
    }

//    private fun getAuthoritySet(): Set<String?>? {
//
//        if (roles == null) {
//            var userAuthorities = authentication.authorities
//            if (roleHierarchy != null) {
//                userAuthorities = roleHierarchy.getReachableGrantedAuthorities(userAuthorities)
//            }
//            roles = AuthorityUtils.authorityListToSet(userAuthorities)
//        }
//        return roles
//    }
//
//    private fun containsAnyAuthorityName(prefix: String, vararg roles: String): Boolean {
//        val roleSet = getAuthoritySet()
//        for (role in roles) {
//            val defaultedRole = getRoleWithDefaultPrefix(prefix, role)
//            if (roleSet.contains(defaultedRole)) {
//                return true
//            }
//        }
//        return false
//    }
}