package com.labijie.infra.oauth2.resource.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("infra.oauth2.resource-server")
class ResourceServerProperties {
    var jwt: ResourceJwtSettings = ResourceJwtSettings()
}