/**
 * @author Anders Xiao
 * @date 2024-06-12
 */
package com.labijie.infra.oauth2.client

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer


interface IOAuth2LoginCustomizer {
    fun customize(configure: OAuth2LoginConfigurer<HttpSecurity>)
}