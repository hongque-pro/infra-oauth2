/**
 * @author Anders Xiao
 * @date 2024-06-18
 */
package com.labijie.infra.oauth2.resource

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.dataformat.smile.databind.SmileMapper
import com.labijie.infra.oauth2.serialization.jackson.OAuth2CommonsJacksonModule
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module
import java.util.*


object CookieUtils {

    private val smileMapper by lazy {
        SmileMapper().apply {
            configure(JsonGenerator.Feature.WRITE_BIGDECIMAL_AS_PLAIN, true)
            configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            configure(SerializationFeature.WRITE_ENUMS_USING_INDEX, true)
            setSerializationInclusion(JsonInclude.Include.NON_NULL)

            registerModules(OAuth2CommonsJacksonModule())
        }
    }

    fun getCookie(request: HttpServletRequest, name: String?): Cookie? {
        val cookies: Array<Cookie>? = request.cookies

        if (!cookies.isNullOrEmpty()) {
            for (cookie in cookies) {
                if (cookie.name.equals(name)) {
                    return cookie
                }
            }
        }

        return null
    }

    fun addCookie(response: HttpServletResponse, name: String?, value: String?, maxAge: Int) {
        val cookie: Cookie = Cookie(name, value)
        cookie.path = "/"
        cookie.isHttpOnly = true
        cookie.maxAge = maxAge
        response.addCookie(cookie)
    }

    fun deleteCookie(request: HttpServletRequest, response: HttpServletResponse, name: String?) {
        val cookies: Array<Cookie>? = request.cookies
        if (!cookies.isNullOrEmpty()) {
            for (cookie in cookies) {
                if (cookie.name.equals(name)) {
                    cookie.value = ""
                    cookie.path = "/"
                    cookie.maxAge = 0
                    response.addCookie(cookie)
                }
            }
        }
    }

    fun serialize(data: Any?): String {

        return Base64.getUrlEncoder()
            .encodeToString(smileMapper.writeValueAsBytes(data))
    }

    fun <T> deserialize(cookie: Cookie, cls: Class<T>): T {
        val cookieValue = Base64.getUrlDecoder().decode(cookie.value)
        return cls.cast(
            smileMapper.readValue(cookieValue, cls)
        )
    }
}