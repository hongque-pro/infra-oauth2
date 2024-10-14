/**
 * @author Anders Xiao
 * @date 2024-06-12
 */
package com.labijie.infra.oauth2.resource.component

import com.labijie.infra.oauth2.resource.configuration.ResourceServerProperties
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer


interface IOAuth2LoginCustomizer {
    fun customize(resourceServerProperties: ResourceServerProperties, configure: OAuth2LoginConfigurer<HttpSecurity>)
}