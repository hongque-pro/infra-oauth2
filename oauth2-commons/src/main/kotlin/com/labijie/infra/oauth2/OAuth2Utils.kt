package com.labijie.infra.oauth2

import com.labijie.infra.utils.throwIfNecessary
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import net.minidev.json.JSONObject
import org.springframework.context.ApplicationContext
import org.springframework.core.io.ClassPathResource
import org.springframework.http.HttpStatus
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import java.io.File
import java.net.URL
import java.util.*
import java.util.stream.Collectors


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-04
 */
object OAuth2Utils {

    /**
     * Default oauth2 server endpoints.
     *
     * @see org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
     */
    object DefaultServerEndpoints {
        const val AUTHORIZATION = "/oauth2/authorize"
        const val PUSHED_AUTHORIZATION_REQUEST = "/oauth2/par"
        const val DEVICE_AUTHORIZATION = "/oauth2/device_authorization"
        const val DEVICE_VERIFICATION = "/oauth2/device_verification"
        const val TOKEN = "/oauth2/token"
        const val JWK_SET = "/oauth2/jwks"
        const val TOKEN_REVOCATION = "/oauth2/revoke"
        const val TOKEN_INTROSPECTION = "/oauth2/introspect"
        const val OIDC_CLIENT_REGISTRATION = "/connect/register"
        const val OIDC_USER_INFO = "/userinfo"
        const val OIDC_LOGOUT_ENDPOINT = "/connect/logout"
    }


    fun HttpServletResponse.writeOAuth2Error(error: OAuth2Error, status: HttpStatus, request: HttpServletRequest? = null) {
        val serverResponse = ServletServerHttpResponse(this)
        serverResponse.setStatusCode(status)

        OAuth2ExceptionHandler.writeError(this, OAuth2AuthenticationException(error), status)
    }

    private lateinit var principalResolvers: List<IPrincipalResolver>
    private lateinit var tokeValueResolvers: List<ITokenValueResolver>

    val PASSWORD_GRANT_TYPE = AuthorizationGrantType("password")

    fun getInfraOAuth2GitProperties(): Properties {
        val systemResources: Enumeration<URL> =
            (OAuth2Utils::class.java.classLoader ?: ClassLoader.getSystemClassLoader()).getResources("git-info/git.properties")
        while (systemResources.hasMoreElements()) {
            systemResources.nextElement().openStream().use { stream ->
                val properties = Properties().apply {
                    this.load(stream)
                }.let {
                    if (it.getProperty("project.group") == "com.labijie.infra" &&
                        it.getProperty("project.name") == "oauth2-commons") {
                        it
                    } else null
                }
                if(properties != null) {
                    return properties
                }
            }
        }
        return Properties()
    }


    internal fun setApplicationContext(applicationContext: ApplicationContext?) {
        if (applicationContext != null && !this::principalResolvers.isInitialized) {
            principalResolvers =
                applicationContext.getBeanProvider(IPrincipalResolver::class.java).stream().collect(Collectors.toList())
            tokeValueResolvers = applicationContext.getBeanProvider(ITokenValueResolver::class.java).stream()
                .collect(Collectors.toList())
        }
    }

    fun JWTClaimsSet.toClaimSet(): ClaimsSet {
        val attributes = this.claims
        return ClaimsSet(JSONObject(attributes))
    }

    fun currentTwoFactorPrincipalOrNull(): TwoFactorPrincipal? {
        return try {
            currentTwoFactorPrincipal()
        }catch (e: BadCredentialsException) {
            null
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
        if (!this::principalResolvers.isInitialized) {
            throw RuntimeException("Spring application context is not ready")
        }

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

    fun <T> loadContent(content: String, action: (content: String)-> T): T?{
        val fromContent = try{
            action(content)
        }catch (e: Throwable) {
            e.throwIfNecessary()
            null
        }

        return fromContent ?: loadFile(content, action) ?: loadResource(content, action)
    }

    private fun <T> loadResource(content: String, action: (content: String) -> T): T? {
        return try {
            val cpr = ClassPathResource(content)
            if(!cpr.exists()) {
                null
            }else {
                val stream = cpr.inputStream
                val c = stream.readBytes().toString(Charsets.UTF_8)
                action(c)
            }
        }catch (rex: Throwable){
            null
        }
    }

    private fun <T> loadFile(content: String, action: (content: String) -> T): T? {
        return try {
            val file = File(content)
           if(file.exists() && file.isFile){
                val fc = file.readBytes().toString(Charsets.UTF_8)
                action(fc)
            }else{
                null
            }
        }catch (rex: Throwable){
            null
        }
    }
}