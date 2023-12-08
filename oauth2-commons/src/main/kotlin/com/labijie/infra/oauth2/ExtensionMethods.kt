package com.labijie.infra.oauth2

import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import java.util.*
import jakarta.servlet.http.HttpServletRequest


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
//val Authentication.isTwoFactorGranted: Boolean
//    get() {
//        val oAuth2Authentication = (this as? AbstractAuthenticationToken)
//
//        val userDetails = (oAuth2Authentication?.userAuthentication?.details as? Map<*, *>)
//        return readIsTwoFactorGranted(userDetails)
//    }
//
//fun Authentication.getAttachedField(propertyName: String): String {
//    val oAuth2Authentication = (this as? OAuth2Authentication)
//
//    val userDetails = (oAuth2Authentication?.userAuthentication?.details as? Map<*, *>)
//    return readAttachedField(userDetails, propertyName)
//}
//
//private fun readAttachedField(details: Map<*, *>?,  fieldName: String): String {
//    return if (!details.isNullOrEmpty()) {
//        val v = details.getOrDefault("${Constants.CLAIM_ATTACHED_FIELD_PREFIX}.$fieldName", "")
//        return (v?.toString()).orEmpty()
//    } else {
//        ""
//    }
//}
//
//private fun readIsTwoFactorGranted(details: Map<*, *>?): Boolean {
//    return if (!details.isNullOrEmpty()) {
//        val v = details.getOrDefault(Constants.CLAIM_TWO_FACTOR, true)
//        if (v is Boolean) {
//            v
//        } else {
//            v.toString().toBoolean()
//        }
//    } else {
//        false
//    }
//}
//
//val Authentication.twoFactorPrincipal: TwoFactorPrincipal
//    get() = OAuth2Utils.getTwoFactorPrincipal(this)

private val log = LoggerFactory.getLogger("oauth2-commons")


val Authentication.twoFactorPrincipal: TwoFactorPrincipal
    get() = OAuth2Utils.getTwoFactorPrincipal(this)

fun extractClientIdAndSecretFromHeader(request: HttpServletRequest): Pair<String, String> {

    val header = request.getHeader("Authorization").orEmpty()

    return extractClientIdAndSecretFromHeaderValue(header)
}

fun extractClientIdAndSecretFromHeaderValue(header: String): Pair<String, String> {
    if (!header.lowercase().startsWith("basic ")) {
        log.warn("Cant find basic authorization header while grant type was '${OAuth2Utils.PASSWORD_GRANT_TYPE}'")
        return Pair("", "")
    }

    val base64Token = header.substring(6).toByteArray(charset("UTF-8"))
    val decoded: ByteArray
    try {
        decoded = Base64.getDecoder().decode(base64Token)
    } catch (e: IllegalArgumentException) {
        log.warn("Failed to decode basic authentication token while grant type was '${OAuth2Utils.PASSWORD_GRANT_TYPE}")
        return Pair("", "")
    }

    val token = String(decoded, Charsets.UTF_8)

    val delim = token.indexOf(":")

    if (delim == -1) {
        log.warn("Failed to decode basic authentication token while grant type was '${OAuth2Utils.PASSWORD_GRANT_TYPE}")
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
    log.warn("Failed to decode basic authentication token while grant type was '${OAuth2Utils.PASSWORD_GRANT_TYPE}")
    return Pair("", "")
}
