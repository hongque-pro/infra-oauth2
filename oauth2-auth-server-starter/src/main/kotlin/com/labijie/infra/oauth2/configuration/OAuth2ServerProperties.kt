package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
@ConfigurationProperties(prefix = "infra.oauth2")
data class OAuth2ServerProperties(
        val token: TokenSettings = TokenSettings(),
        var scopeValidationEnabled: Boolean = false
)