package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorExpressionRoot
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.JwtClaimAccessor
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken
import org.springframework.util.Assert


val JwtClaimAccessor.twoFactorGranted: Boolean?
get() = this.getClaimAsBoolean(Constants.CLAIM_TWO_FACTOR)

val JwtClaimAccessor.userId: String?
    get() = this.getClaimAsString(Constants.CLAIM_USER_ID) ?: ""

val JwtClaimAccessor.roles: List<String>
    get() = this.getClaimAsStringList(Constants.CLAIM_ROLES) ?: listOf()


fun ExpressionUrlAuthorizationConfigurer<*>.MvcMatchersAuthorizedUrl.hasScope(scope: String?): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    Assert.notNull(scope, "scope cannot be null")
    Assert.isTrue(!scope!!.startsWith("SCOPE_")
    ) { "scope should not start with 'SCOPE_' since it is automatically inserted. Got '$scope'" }
    val expr = "hasRole('SCOPE__$scope')"
    return this.access("hasScope('$scope')")
}

fun ExpressionUrlAuthorizationConfigurer<*>.AuthorizedUrl.hasAttachedFiledValue(fieldName: String, value:String): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    return this.access("${OAuth2TwoFactorExpressionRoot::hasAttachedFieldValue.name}('$fieldName','$value')")
}

fun ExpressionUrlAuthorizationConfigurer<*>.AuthorizedUrl.twoFactorRequired(): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    return this.access("${OAuth2TwoFactorExpressionRoot::twoFactorRequired.name}()")
}




val Authentication.isTwoFactorGranted: Boolean
    get() {
        val oAuth2Authentication = (this as? AbstractOAuth2TokenAuthenticationToken<*>)
        if (oAuth2Authentication != null) {
            return readIsTwoFactorGranted(oAuth2Authentication.tokenAttributes)
        }
        return false
    }

fun Authentication.getAttachedField(propertyName: String): String {
    val oAuth2Authentication =(this as? AbstractOAuth2TokenAuthenticationToken<*>)

    val userDetails = (oAuth2Authentication?.tokenAttributes as? Map<*, *>)
    return readAttachedField(userDetails, propertyName)
}

private fun readAttachedField(details: Map<*, *>?,  fieldName: String): String {
    return if (!details.isNullOrEmpty()) {
        val v = details.getOrDefault(fieldName, "")
        return (v?.toString()).orEmpty()
    } else {
        ""
    }
}

private fun readIsTwoFactorGranted(details: Map<*, *>?): Boolean {
    return if (!details.isNullOrEmpty()) {
        val v = details.getOrDefault(Constants.CLAIM_TWO_FACTOR, true)
        if (v is Boolean) {
            v
        } else {
            v.toString().toBoolean()
        }
    } else {
        false
    }
}



