/**
 * @author Anders Xiao
 * @date 2023-12-29
 */
package com.labijie.infra.oauth2.customizer

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext


interface IJwtCustomizer {
    fun customizeToken(context: JwtEncodingContext)
}