package com.labijie.infra.oauth2.filter

import com.labijie.infra.oauth2.OAuth2Utils
import org.springframework.core.MethodParameter
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.web.bind.support.WebDataBinderFactory
import org.springframework.web.context.request.NativeWebRequest
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.method.support.ModelAndViewContainer

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
class ClientDetailsArgumentResolver(private val clientDetailsService: ClientDetailsService) : HandlerMethodArgumentResolver {
    override fun supportsParameter(parameter: MethodParameter): Boolean {
        val type = parameter.parameterType
        return ClientDetails::class.java == type
    }

    override fun resolveArgument(parameter: MethodParameter, mavContainer: ModelAndViewContainer?, webRequest: NativeWebRequest, binderFactory: WebDataBinderFactory?): Any? {
        val clientDetails = ClientDetailsHolder.getClient()
        if (clientDetails != null) {
            return clientDetails
        }
        //优先从 oauth 授权信息中获取
        val auth = SecurityContextHolder.getContext().authentication as? OAuth2Authentication
        if (auth != null && auth.isAuthenticated) {
            val clientId = auth.oAuth2Request.clientId
            return clientDetailsService.loadClientByClientId(clientId)
        }

        //从 header basic 信息中获取
        val headerValue = webRequest.getHeader("Authorization").orEmpty()
        val (clientId, _) = OAuth2Utils.extractClientIdAndSecretFromHeaderValue(headerValue)
        return if (clientId.isBlank()) null else clientDetailsService.loadClientByClientId(clientId)

    }
}