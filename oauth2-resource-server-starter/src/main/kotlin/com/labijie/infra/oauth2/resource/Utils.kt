package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.OAuth2Constants
import com.labijie.infra.oauth2.resource.expression.OAuth2ExpressionAuthorizationManager
import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorExpressionRoot
import org.springframework.security.authorization.AuthorityAuthorizationManager
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.JwtClaimAccessor
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.util.Assert
import org.springframework.util.StringUtils


val JwtClaimAccessor.twoFactorGranted: Boolean?
    get() = this.getClaimAsBoolean(OAuth2Constants.CLAIM_TWO_FACTOR)

val JwtClaimAccessor.userId: String
    get() = this.getClaimAsString(OAuth2Constants.CLAIM_USER_ID) ?: ""

val JwtClaimAccessor.roles: List<String>
    get() = this.getClaimAsStringList(OAuth2Constants.CLAIM_ROLES) ?: listOf()


fun AuthorizeHttpRequestsConfigurer<*>.AuthorizedUrl.hasScope(scope: String): AuthorizeHttpRequestsConfigurer<*>.AuthorizationManagerRequestMatcherRegistry {
    Assert.notNull(scope, "scope cannot be null")
    Assert.isTrue(!scope.startsWith(OAuth2Constants.SCOPE_AUTHORITY_PREFIX)) { "scope should not start with '${OAuth2Constants.SCOPE_AUTHORITY_PREFIX}' since it is automatically inserted. Got '$scope'" }
    return this.hasAuthority("${OAuth2Constants.SCOPE_AUTHORITY_PREFIX}$scope")
}


fun AuthorizeHttpRequestsConfigurer<*>.AuthorizedUrl.hasAnyScope(vararg scopes: String): AuthorizeHttpRequestsConfigurer<*>.AuthorizationManagerRequestMatcherRegistry {
    val anyAuthorities = StringUtils.arrayToDelimitedString(scopes, "','${OAuth2Constants.SCOPE_AUTHORITY_PREFIX}")

    AuthorityAuthorizationManager.hasAnyAuthority<RequestAuthorizationContext>(anyAuthorities)
    return this.hasAnyAuthority("${OAuth2Constants.SCOPE_AUTHORITY_PREFIX}$anyAuthorities")
}

fun AuthorizeHttpRequestsConfigurer<*>.AuthorizedUrl.hasTokenAttributeValue(attribute: String, value: String): AuthorizeHttpRequestsConfigurer<*>.AuthorizationManagerRequestMatcherRegistry {
    return this.access(OAuth2ExpressionAuthorizationManager("${OAuth2TwoFactorExpressionRoot::hasTokenAttributeValue.name}('$attribute','$value')"))
}

fun AuthorizeHttpRequestsConfigurer<*>.AuthorizedUrl.hasTokenAttribute(attribute: String): AuthorizeHttpRequestsConfigurer<*>.AuthorizationManagerRequestMatcherRegistry {
    return this.access(OAuth2ExpressionAuthorizationManager("${OAuth2TwoFactorExpressionRoot::hasTokenAttribute.name}('$attribute')"))
}

fun AuthorizeHttpRequestsConfigurer<*>.AuthorizedUrl.twoFactorRequired(): AuthorizeHttpRequestsConfigurer<*>.AuthorizationManagerRequestMatcherRegistry {
    return this.access(OAuth2ExpressionAuthorizationManager("${OAuth2TwoFactorExpressionRoot::twoFactorRequired.name}()"))
}


val Authentication.isTwoFactorGranted: Boolean
    get() {
        val oAuth2Authentication = (this as? AbstractOAuth2TokenAuthenticationToken<*>)
        if (oAuth2Authentication != null) {
            return readIsTwoFactorGranted(oAuth2Authentication.tokenAttributes)
        }
        return false
    }

fun Authentication.getTokenAttributes(attribute: String): Any? {
    val oAuth2Authentication = (this as? AbstractOAuth2TokenAuthenticationToken<*>)

    val userDetails = (oAuth2Authentication?.tokenAttributes as? Map<*, *>)
    return userDetails?.get(attribute)
}


private fun readIsTwoFactorGranted(details: Map<*, *>?): Boolean {
    return if (!details.isNullOrEmpty()) {
        val v = details.getOrDefault(OAuth2Constants.CLAIM_TWO_FACTOR, true)
        if (v is Boolean) {
            v
        } else {
            v.toString().toBoolean()
        }
    } else {
        false
    }
}



