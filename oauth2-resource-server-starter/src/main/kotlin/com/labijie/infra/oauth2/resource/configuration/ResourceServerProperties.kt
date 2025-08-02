package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.configuration.CsrfSettings
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty

@ConfigurationProperties("infra.oauth2.resource-server")
class ResourceServerProperties {
    companion object {
        const val PUBLIC_KEY_CONFIG_PATH = "infra.oauth2.resource-server.jwt.rsa-pub-key"
    }

    @NestedConfigurationProperty
    val jwt: ResourceJwtSettings = ResourceJwtSettings()

    @NestedConfigurationProperty
    val bearerTokenResolver = BearerTokenResolverSettings()
}