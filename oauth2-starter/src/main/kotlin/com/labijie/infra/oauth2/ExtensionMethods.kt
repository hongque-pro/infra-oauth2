package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.security.OAuth2TwoFactorExpressionRoot
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.OAuth2Authentication


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
val Authentication.isTwoFactorGranted: Boolean
    get() {
        val oAuth2Authentication = (this as? OAuth2Authentication)

        val userDetails = (oAuth2Authentication?.userAuthentication?.details as? Map<*, *>)
        return readIsTwoFactorGranted(userDetails)
    }

fun Authentication.getAttachedField(propertyName: String): String {
    val oAuth2Authentication = (this as? OAuth2Authentication)

    val userDetails = (oAuth2Authentication?.userAuthentication?.details as? Map<*, *>)
    return readAttachedField(userDetails, propertyName)
}

private fun readAttachedField(details: Map<*, *>?,  fieldName: String): String {
    return if (!details.isNullOrEmpty()) {
        val v = details.getOrDefault("${Constants.TOKEN_ATTACHED_FIELD_PREFIX}.$fieldName", "")
        return (v?.toString()).orEmpty()
    } else {
        ""
    }
}

private fun readIsTwoFactorGranted(details: Map<*, *>?): Boolean {
    return if (!details.isNullOrEmpty()) {
        val v = details.getOrDefault(Constants.USER_TWO_FACTOR_PROPERTY, true)
        if (v is Boolean) {
            v
        } else {
            v.toString().toBoolean()
        }
    } else {
        false
    }
}

val Authentication.twoFactorPrincipal: TwoFactorPrincipal
    get() = OAuth2Utils.getTwoFactorPrincipal(this)

fun ExpressionUrlAuthorizationConfigurer<*>.AuthorizedUrl.hasAttachedFiledValue(fieldName: String, value:String): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    return this.access("${OAuth2TwoFactorExpressionRoot::hasAttachedFieldValue.name}('$fieldName','$value')")
}

fun ExpressionUrlAuthorizationConfigurer<*>.AuthorizedUrl.twoFactorRequired(): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    return this.access("${OAuth2TwoFactorExpressionRoot::twoFactorRequired.name}()")
}

fun ExpressionUrlAuthorizationConfigurer<*>.AuthorizedUrl.hasScope(scope: String): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    return this.access("#oauth2.hasScope('$scope')")
}

fun ExpressionUrlAuthorizationConfigurer<*>.AuthorizedUrl.isClient(): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    return this.access("#oauth2.isClient()")
}

fun ExpressionUrlAuthorizationConfigurer<*>.AuthorizedUrl.hasClientRole(role: String): ExpressionUrlAuthorizationConfigurer<*>.ExpressionInterceptUrlRegistry {
    return this.access("#oauth2.clientHasRole('$role')")
}
