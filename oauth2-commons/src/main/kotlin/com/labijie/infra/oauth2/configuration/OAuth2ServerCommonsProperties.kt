package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/2
 *
 */
@ConfigurationProperties("infra.oauth2")
class OAuth2ServerCommonsProperties {
    @NestedConfigurationProperty
    var csrf: CsrfSettings = CsrfSettings()
}