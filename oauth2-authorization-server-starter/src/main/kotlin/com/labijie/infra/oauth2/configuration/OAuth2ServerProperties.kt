package com.labijie.infra.oauth2.configuration

import com.nimbusds.oauth2.sdk.id.Issuer
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty
import java.net.URI

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
    val defaultClient: DefaultClientProperties = DefaultClientProperties(),

    var clientRepository: String = "memory",
    var scopeValidationEnabled: Boolean = false,
    var createJdbcSchema: Boolean = false,
//    var issuer: URI? = null
) {
    companion object {
        const val PRIVATE_KEY_PROPERTY_PATH = "infra.oauth2.token.jwt.rsa.private-key"
        const val PUBLIC_KEY_PROPERTY_PATH = "infra.oauth2.token.jwt.rsa.public-key"
        //const val AUTHORIZATION_SERVICE_PROPERTY_PATH = "infra.oauth2.authorization-service"
        const val AUTHORIZATION_SERVICE_PROPERTY_PATH = "spring.security.oauth2.authorizationserver.issuer"

        const val ISSUER_KEY_PROPERTY_PATH = "infra.oauth2.authorization-server.issuer"
    }
}