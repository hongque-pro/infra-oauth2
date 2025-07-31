package com.labijie.infra.oauth2.mvc

import com.fasterxml.jackson.annotation.JsonProperty
import com.labijie.infra.oauth2.AccessToken

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/1
 *
 */
data class OidcLoginResultResponse(
    val error: String? = null,
    @get:JsonProperty("error_description")
    val errorDescription: String? = null,

    //登录失败时，将第三方账号信息生成一个 Oidc Token
    val idToken: String? = null,

    //成功时，生成 accessToken
    var accessToken: AccessToken? = null
)