package com.labijie.infra.oauth2

import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 17:40
 * @Description:
 */
interface ITokenIntrospectParser {
    fun parse(token: String) : TokenIntrospectionResponse
}