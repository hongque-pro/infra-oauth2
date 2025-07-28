package com.labijie.infra.oauth2.client.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */
@ConfigurationProperties("infra.oauth2.authorization-server.client")
class InfraOAuth2ClientProperties {

    var oidcLoginEnabled: Boolean = true

    var oidcLogin: MutableMap<String, OAuth2ClientOidcLoginProperties> = mutableMapOf()
}