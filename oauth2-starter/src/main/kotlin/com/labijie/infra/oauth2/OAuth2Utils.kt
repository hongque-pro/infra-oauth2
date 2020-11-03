package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.Constants.USER_ID_PROPERTY
import com.labijie.infra.oauth2.Constants.USER_TWO_FACTOR_PROPERTY
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.provider.OAuth2Authentication
import java.util.*
import javax.servlet.http.HttpServletRequest
import kotlin.jvm.Throws

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-04
 */
object OAuth2Utils {

    private val log = LoggerFactory.getLogger(OAuth2Utils::class.java)

    @Throws(BadCredentialsException::class)
    fun currentTwoFactorPrincipal(): TwoFactorPrincipal {
        val context = SecurityContextHolder.getContext()
        return getTwoFactorPrincipal(context.authentication)
    }

//    @Throws(BadCredentialsException::class)
//    fun currentTwoFactorPrincipalAsync(): Mono<TwoFactorPrincipal> {
//        val context = ReactiveSecurityContextHolder.getContext()
//        return context.map {
//            getTwoFactorPrincipal(it.authentication)
//        }
//    }

    @Throws(BadCredentialsException::class)
    internal fun getTwoFactorPrincipal(authentication:Authentication): TwoFactorPrincipal{

        val userAuthentication = if (authentication is OAuth2Authentication){
            authentication.userAuthentication //带 token 请求时
        }else{
            authentication //登录成功时
        }

        val map = userAuthentication.details as? Map<*,*> ?: throw BadCredentialsException("Current authentication dose not contains any user details")
        val attachments = mutableMapOf<String, String>()
        map.filter { kv -> kv.key != null && kv.key.toString().startsWith(Constants.TOKEN_ATTACHED_FIELD_PREFIX) && kv.value != null }.forEach {
            val key = it.key.toString().removePrefix(Constants.TOKEN_ATTACHED_FIELD_PREFIX)
            if(key.isNotBlank() && it.value != null){
                attachments[key] = it.value.toString()
            }
        }

        return TwoFactorPrincipal(
                map.getOrDefault(USER_ID_PROPERTY, "").toString(),
                userAuthentication.name,
                isTwoFactorGranted = map.getOrDefault(USER_TWO_FACTOR_PROPERTY, "false").toString().toBoolean(),
                authorities = userAuthentication.authorities,
                attachedFields = attachments
        )
    }

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

    fun extractClientIdAndSecretFromHeader(request: HttpServletRequest): Pair<String, String> {

        val header = request.getHeader("Authorization").orEmpty()

        return extractClientIdAndSecretFromHeaderValue(header)
    }

    fun extractClientIdAndSecretFromHeaderValue(header: String): Pair<String, String> {
        if (!header.toLowerCase().startsWith("basic ")) {
            log.warn("Cant find basic authorization header while grant type was '${Constants.GRANT_TYPE_PASSWORD}'")
            return Pair("", "")
        }

        val base64Token = header.substring(6).toByteArray(charset("UTF-8"))
        val decoded: ByteArray
        try {
            decoded = Base64.getDecoder().decode(base64Token)
        } catch (e: IllegalArgumentException) {
            log.warn("Failed to decode basic authentication token while grant type was '${Constants.GRANT_TYPE_PASSWORD}")
            return Pair("", "")
        }

        val token = String(decoded, Charsets.UTF_8)

        val delim = token.indexOf(":")

        if (delim == -1) {
            log.warn("Failed to decode basic authentication token while grant type was '${Constants.GRANT_TYPE_PASSWORD}")
            return Pair("", "")
        }
        //return arrayOf(token.substring(0, delim), token.substring(delim + 1))
        val strings = token.split(":")
        if (strings.count() == 1) {
            return Pair(strings.first(), "")
        }
        if (strings.count() == 2) {
            return Pair(strings.first(), strings.last())
        }
        log.warn("Failed to decode basic authentication token while grant type was '${Constants.GRANT_TYPE_PASSWORD}")
        return Pair("", "")
    }
}