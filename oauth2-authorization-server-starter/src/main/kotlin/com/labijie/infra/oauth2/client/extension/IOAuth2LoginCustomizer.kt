package com.labijie.infra.oauth2.client.extension

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer

/**
 * @author Anders Xiao
 * @date 2024-06-12
 */
interface IOAuth2LoginCustomizer {
    fun customize(configure: OAuth2LoginConfigurer<HttpSecurity>)
}