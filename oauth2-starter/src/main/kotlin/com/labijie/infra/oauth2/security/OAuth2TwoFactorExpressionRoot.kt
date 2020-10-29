package com.labijie.infra.oauth2.security

import com.labijie.infra.oauth2.getAttachedField
import com.labijie.infra.oauth2.isTwoFactorGranted
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

    fun hasAttachedFieldValue(fieldName:String, value: String): Boolean {
        return this.authentication.getAttachedField(fieldName) == value
    }
}