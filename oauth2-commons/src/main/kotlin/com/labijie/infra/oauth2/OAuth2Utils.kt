package com.labijie.infra.oauth2

import org.springframework.context.ApplicationContext
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import java.lang.RuntimeException
import java.util.stream.Collectors
import kotlin.jvm.Throws

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-04
 */
object OAuth2Utils {

    private lateinit var principalResolvers: List<IPrincipalResolver>
    private lateinit var tokeValueResolvers: List<ITokenValueResolver>

    internal fun setApplicationContext(applicationContext: ApplicationContext?) {
        if (applicationContext != null && !this::principalResolvers.isInitialized) {
            principalResolvers =
                applicationContext.getBeanProvider(IPrincipalResolver::class.java).stream().collect(Collectors.toList())
            tokeValueResolvers = applicationContext.getBeanProvider(ITokenValueResolver::class.java).stream()
                .collect(Collectors.toList())
        }
    }

    @Throws(BadCredentialsException::class)
    fun currentTwoFactorPrincipal(): TwoFactorPrincipal {
        if (!this::principalResolvers.isInitialized) {
            throw RuntimeException("Spring application context is not ready")
        }

        val authentication = SecurityContextHolder.getContext()?.authentication
            ?: throw BadCredentialsException("Current environment dose not contains any SecurityContext")

        return getTwoFactorPrincipal(authentication)
    }

    fun getTwoFactorPrincipal(authentication: Authentication): TwoFactorPrincipal {
        val r = principalResolvers.firstOrNull { it.support(authentication) }
            ?: throw BadCredentialsException("Current authentication dose not contains any user details")
        return r.resolvePrincipal(authentication)
    }

    fun getTokenValue(authentication: Authentication): String? {
        val r = tokeValueResolvers.firstOrNull { it.support(authentication) }
        return r?.resolveToken(authentication)
    }

//    @Throws(BadCredentialsException::class)
//    fun currentTwoFactorPrinciplAsync(): Mono<TwoFactorPrincipal> {
//        val context = ReactiveSecurityContextHolder.getContext()
//        return context.map {
//            getTwoFactorPrincipal(it.authentication)
//        }
//    }


//    fun extractClientId(request: HttpServletRequest): String {
//        val grantType = request.getParameter("grant_type")
//        return when (grantType) {
//            Constants.GRANT_TYPE_IMPLICIT,
//            Constants.GRANT_TYPE_CLIENT_CREDENTIALS,
//            Constants.GRANT_TYPE_AUTHORIZATION_CODE -> request.getParameter("client_id")
//            Constants.GRANT_TYPE_PASSWORD -> extractClientIdAndSecretFromHeader(request).first
//            else -> ""
//        }
//    }
}