/**
 * @author Anders Xiao
 * @date 2023-12-29
 */
package com.labijie.infra.oauth2.customizer

import org.springframework.beans.factory.ObjectProvider
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer


class InfraJwtEncodingContextCustomizer(private val jwtCustomizers: ObjectProvider<IJwtCustomizer>) : OAuth2TokenCustomizer<JwtEncodingContext> {
    override fun customize(context: JwtEncodingContext?) {
        if(context != null) {
            jwtCustomizers.orderedStream().forEach {
                it.customizeToken(context)
            }
        }
    }
}