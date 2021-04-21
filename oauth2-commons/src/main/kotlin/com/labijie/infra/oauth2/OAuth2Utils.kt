package com.labijie.infra.oauth2

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.context.ApplicationContext
import org.springframework.context.EnvironmentAware
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

    private lateinit var resolvers: List<IPrincipalResolver>

    internal fun setApplicationContext(applicationContext: ApplicationContext?){
        if (applicationContext != null && !this::resolvers.isInitialized){
           resolvers = applicationContext.getBeanProvider(IPrincipalResolver::class.java).stream().collect(Collectors.toList())
        }
    }

    @Throws(BadCredentialsException::class)
    fun currentTwoFactorPrincipal(): TwoFactorPrincipal {
        if (!this::resolvers.isInitialized){
            throw RuntimeException("Spring application context is not ready")
        }

        val authentication = SecurityContextHolder.getContext()?.authentication ?: throw BadCredentialsException("Current environment dose not contains any SecurityContext")

        return getTwoFactorPrincipal(authentication)
    }

    internal fun getTwoFactorPrincipal(authentication: Authentication): TwoFactorPrincipal {
        val r = resolvers.firstOrNull { it.support(authentication) }
                ?: throw BadCredentialsException("Current authentication dose not contains any user details")
        return r.resolvePrincipal(authentication)
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