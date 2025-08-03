package com.labijie.infra.oauth2.mvc

import com.fasterxml.jackson.annotation.JsonProperty

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/3
 *
 */
abstract class ErrorOptionalResponse(
    val error: String? = null,
    @get:JsonProperty("error_description")
    val errorDescription: String? = null
)