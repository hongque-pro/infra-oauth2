package com.labijie.infra.oauth2.endpoint

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.ITokenIntrospectParser
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody
import java.util.*
import java.util.stream.Collectors


/**
 * support any token Introspection endpoint
 * @Auther: AndersXiao
 * @Date: 2021-04-22 9:56
 * @Description:
 */
@FrameworkEndpoint
internal class IntrospectEndpoint(private val introspectParser: ITokenIntrospectParser) {

    @PostMapping(Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH)
    @ResponseBody
    fun introspect(@RequestParam("token", required = true) token: String): Map<String, Any> {
        val resp = introspectParser.parse(token)
        return if (resp.indicatesSuccess()){
            resp.toSuccessResponse().toJSONObject()
        }else{
            resp.toErrorResponse().errorObject.toJSONObject()
        }
    }
}