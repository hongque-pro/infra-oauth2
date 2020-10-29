package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
@ConfigurationProperties("infra.oauth2")
data class OAuth2ServerConfig(
        var token:TokenSettings = TokenSettings()
)