package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
@ConfigurationProperties(prefix = "infra.oauth2.authorization-server")
data class OAuth2ServerProperties(
    @NestedConfigurationProperty
    val token: TokenProperties = TokenProperties(),

    @NestedConfigurationProperty
    val authorizationService: AuthorizationServiceProperties = AuthorizationServiceProperties(),


    @NestedConfigurationProperty
    val serverClient: OAuth2ServerClientProperties = OAuth2ServerClientProperties(),

    var scopeValidationEnabled: Boolean = false,
    var createJdbcSchema: Boolean = false,
//    var issuer: URI? = null

) {

    companion object {
        const val PRIVATE_KEY_PROPERTY_PATH = "infra.oauth2.authorization-server.token.jwt.rsa.private-key"
        const val PUBLIC_KEY_PROPERTY_PATH = "infra.oauth2.authorization-server.token.jwt.rsa.public-key"

        const val ISSUER_KEY_PROPERTY_PATH = "spring.security.oauth2.authorizationserver.issuer"
    }
}