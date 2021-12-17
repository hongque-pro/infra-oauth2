package com.labijie.infra.oauth2

import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/17
 * @Description:
 */
class InfraAuthenticationFailureHandler : AuthenticationFailureHandler {
    override fun onAuthenticationFailure(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        exception: AuthenticationException?
    ) {

    }

    //    protected class OAuth2Error(
//        var error: String,
//        errorDescription: String?,
//        private val httpCode: Int = 401
//    ) : OAuth2Exception(errorDescription) {
//
//        companion object {
//            @JvmStatic
//            val UnhandledError: OAuth2Exception =
//                OAuth2Error(ApplicationErrors.UnhandledError, "unhandled oatuh2 error", 500)
//        }
//
//        constructor(errorCode: String):this(errorCode, errorCode)
//
//        override fun getHttpErrorCode() = httpCode
//
//        @get: JsonProperty("description")
//        override val message: String?
//            get() = super.message
//
//        @JsonIgnore
//        override fun getLocalizedMessage(): String {
//            return super.getLocalizedMessage()
//        }
//
//        @JsonIgnore
//        override fun getOAuth2ErrorCode(): String {
//            return this.error
//        }
//    }
}