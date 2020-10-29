package com.labijie.infra.oauth2.filter

import com.labijie.infra.oauth2.OAuth2Utils
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter
import java.lang.Exception
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
class ClientDetailsInterceptorAdapter(private val clientDetailsService: ClientDetailsService): HandlerInterceptorAdapter() {

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        val method = handler as? HandlerMethod
        if(method != null){
            val annotation = method.getMethodAnnotation(ClientRequired::class.java)
            if(annotation != null){
                val (clientId, secret) = OAuth2Utils.extractClientIdAndSecretFromHeader(request)
                if(clientId.isBlank()){
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "client id and secret required")
                    return false
                }
                else{
                    val clientDetail = clientDetailsService.loadClientByClientId(clientId)
                    if(clientDetail.isSecretRequired && !clientDetail.clientSecret.orEmpty().equals(secret, ignoreCase = false)){
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "invalid client")
                        return false
                    }
                    ClientDetailsHolder.setContext(clientDetail)
                }
            }
        }
        return true
    }

    override fun afterCompletion(request: HttpServletRequest, response: HttpServletResponse, handler: Any, ex: Exception?) {
        ClientDetailsHolder.clearContext()
        super.afterCompletion(request, response, handler, ex)
    }
}