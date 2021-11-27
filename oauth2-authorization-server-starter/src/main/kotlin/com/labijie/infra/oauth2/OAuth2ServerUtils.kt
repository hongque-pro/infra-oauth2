package com.labijie.infra.oauth2

import com.sun.org.apache.bcel.internal.generic.RETURN
import org.springframework.security.oauth2.core.AbstractOAuth2Token
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.util.StringUtils
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.concurrent.TimeUnit

object OAuth2ServerUtils {

    fun Long?.toInstant(unit: TimeUnit = TimeUnit.SECONDS): Instant? {
        if (this == null){
            return null
        }
        val seconds = unit.toSeconds(this)
        return Instant.ofEpochSecond(seconds)
    }

    fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

    fun String.md5Hex(): String{
        val md = MessageDigest.getInstance("md5");
        return md.digest(this.toByteArray(Charsets.UTF_8)).toHexString()
    }

    fun generateRefreshToken(tokenTimeToLive: Duration): OAuth2RefreshToken? {
        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(tokenTimeToLive)
        return OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, expiresAt)
    }

    fun OAuth2AccessTokenAuthenticationToken.toResponse(): Map<String, Any> {

        val parameters: MutableMap<String, Any> = HashMap()
        parameters[OAuth2ParameterNames.ACCESS_TOKEN] = accessToken.tokenValue
        parameters[OAuth2ParameterNames.TOKEN_TYPE] = accessToken.tokenType.value
        parameters[OAuth2ParameterNames.EXPIRES_IN] = getExpiresIn(accessToken)
        if (accessToken.scopes.isNotEmpty()) {
            parameters[OAuth2ParameterNames.SCOPE] =
                StringUtils.collectionToDelimitedString(accessToken.scopes, " ")
        }
        val refreshTv = refreshToken?.tokenValue
        if (!refreshTv.isNullOrBlank()) {
            parameters[OAuth2ParameterNames.REFRESH_TOKEN] = refreshTv
        }
        val params = additionalParameters
        if (params.isNotEmpty()) {
            for ((key, value) in params.entries) {
                parameters[key] = value
            }
        }
        return parameters
    }

    private fun getExpiresIn(token: AbstractOAuth2Token): Long {
        return if (token.expiresAt != null) {
            ChronoUnit.SECONDS.between(Instant.now(), token.expiresAt)
        } else -1
    }
}