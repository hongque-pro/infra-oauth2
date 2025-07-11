package com.labijie.infra.oauth2.testing.component

import com.labijie.dummy.auth.DummyConstants
import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.configuration.DefaultClientProperties
import com.labijie.infra.utils.logger
import org.junit.jupiter.api.Assertions
import org.springframework.http.HttpHeaders
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import kotlin.reflect.KClass

object OAuth2TestingUtils {
    var passwordEncoder: PasswordEncoder = BCryptPasswordEncoder()
    private val defaultClient = DefaultClientProperties()


    val TestUser: ITwoFactorUserDetails = object: ITwoFactorUserDetails {

        private val passwordHash = passwordEncoder.encode(DummyConstants.userPassword)

        override fun getUserId(): String {
            return "123456789"
        }

        override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
            return mutableListOf(SimpleGrantedAuthority("ROLE_aa"))
        }

        override fun isEnabled(): Boolean = true

        override fun getUsername(): String = DummyConstants.username

        override fun isCredentialsNonExpired(): Boolean = true

        override fun getPassword(): String = passwordHash

        override fun isAccountNonExpired(): Boolean = true

        override fun isAccountNonLocked(): Boolean = true

        override fun isTwoFactorEnabled(): Boolean = true

        override fun getTokenAttributes(): Map<String, String> {
            return mapOf("aaa" to "test")
        }
    }


    fun ResultActions.readToMap(logResult: Boolean = true): Map<String, Any> {
        val resultString = this.andReturn().response.contentAsString
        val map = JacksonHelper.deserializeMap(resultString.toByteArray(Charsets.UTF_8), String::class, Any::class)
        if (logResult) {
            val pretty = JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map)
            val url = this.andReturn().request.requestURI
            val log = arrayOf(System.lineSeparator(), url, "[Json Response]", pretty).joinToString(System.lineSeparator())
            logger.debug(log)
        }
        return map
    }

    fun <T:Any> ResultActions.readToObject(clazz: KClass<T>): T {
        val json = this.andReturn().response.contentAsString
        return JacksonHelper.defaultObjectMapper.readValue(json, clazz.java)
    }

    fun ResultActions.readTokenValue(): String {
        val tokenResult = this.readToMap()
        logger.info(System.lineSeparator() + JacksonHelper.defaultObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(tokenResult))
        Assertions.assertTrue(tokenResult.containsKey("access_token"))

        val tv = tokenResult["access_token"]?.toString()

        Assertions.assertTrue(!tv.isNullOrBlank(), "access_token can not be null or blank")
        return tv.orEmpty()
    }

    fun ResultActions.readString(logResult: Boolean = true): String {
        val s = this.andReturn().response.contentAsString

        if (logResult) {
            logger.info("Http Result: ${System.lineSeparator()}$s")
        }
        return s
    }

    fun <T : Any> ResultActions.readAs(type: KClass<T>): T {
        val resultString = this.andReturn().response.contentAsString
        return JacksonHelper.deserialize(resultString.toByteArray(Charsets.UTF_8), type)
    }

    fun MockHttpServletRequestBuilder.withBearerToken(token: String?): MockHttpServletRequestBuilder {
        if (token.isNullOrBlank()) {
            return this
        }
        return this.header(HttpHeaders.AUTHORIZATION, "Bearer $token")
    }
}