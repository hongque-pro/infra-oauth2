package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.NestedConfigurationProperty

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/3
 *
 */
class OAuth2ServerClientProperties {
    var repository: String = "memory"

    @NestedConfigurationProperty
    val defaultClient: DefaultClientProperties = DefaultClientProperties()
}