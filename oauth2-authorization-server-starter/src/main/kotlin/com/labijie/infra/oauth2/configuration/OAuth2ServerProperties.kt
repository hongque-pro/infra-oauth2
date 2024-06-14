package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
@ConfigurationProperties(prefix = "infra.oauth2")
data class OAuth2ServerProperties(
    var issuer: String = "https://labijie.com",

    @NestedConfigurationProperty
    val token: TokenProperties = TokenProperties(),

    @NestedConfigurationProperty
    val authorizationService: AuthorizationServiceProperties = AuthorizationServiceProperties(),

    var clientRepository: String = "memory",
    val defaultClient: DefaultClientProperties = DefaultClientProperties(),
    var scopeValidationEnabled: Boolean = false,
    var createJdbcSchema: Boolean = false
) {
    companion object {
        const val PRIVATE_KEY_PROPERTY_PATH = "infra.oauth2.token.jwt.rsa.private-key"
        const val PUBLIC_KEY_PROPERTY_PATH = "infra.oauth2.token.jwt.rsa.public-key"
        const val AUTHORIZATION_SERVICE_PROPERTY_PATH = "infra.oauth2.authorization-service"
    }
}