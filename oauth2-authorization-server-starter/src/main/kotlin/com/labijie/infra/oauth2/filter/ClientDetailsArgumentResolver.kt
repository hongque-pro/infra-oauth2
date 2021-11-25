package com.labijie.infra.oauth2.filter

import com.labijie.infra.oauth2.extractClientIdAndSecretFromHeaderValue
import org.springframework.core.MethodParameter
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.web.bind.support.WebDataBinderFactory
import org.springframework.web.context.request.NativeWebRequest
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.method.support.ModelAndViewContainer

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
class ClientDetailsArgumentResolver(private val registeredClientRepository: RegisteredClientRepository) : HandlerMethodArgumentResolver {
    override fun supportsParameter(parameter: MethodParameter): Boolean {
        val type = parameter.parameterType
        return RegisteredClient::class.java == type
    }

    override fun resolveArgument(parameter: MethodParameter, mavContainer: ModelAndViewContainer?, webRequest: NativeWebRequest, binderFactory: WebDataBinderFactory?): Any? {
        val clientDetails = ClientDetailsHolder.getClient()
        if (clientDetails != null) {
            return clientDetails
        }


        //从 header basic 信息中获取
        val headerValue = webRequest.getHeader("Authorization").orEmpty()
        val (clientId, _) = extractClientIdAndSecretFromHeaderValue(headerValue)
        return if (clientId.isBlank()) null else registeredClientRepository.findByClientId(clientId) ?: throw OAuth2AuthenticationException(
            OAuth2ErrorCodes.INVALID_CLIENT)

    }
}