package com.labijie.infra.oauth2.resource.configuration

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("infra.oauth2.resource-server")
class ResourceServerProperties {
    companion object {
        const val PUBLIC_KEY_CONFIG_PATH = "infra.oauth2.resource-server.jwt.rsa-pub-key"
    }

    var jwt: ResourceJwtSettings = ResourceJwtSettings()
    var bearerTokenResolver = BearerTokenResolverSettings()
    var loginUrl: String = "/oauth2/unauthorized"

}