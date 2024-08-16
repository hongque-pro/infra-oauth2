/**
 * @author Anders Xiao
 * @date 2023-12-29
 */
package com.labijie.infra.oauth2.customizer

import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer


class InfraOAuth2JwtTokenCustomizer : OAuth2TokenCustomizer<JwtEncodingContext>, ApplicationContextAware {

    private var applicationContext: ApplicationContext? = null

    private val customizers by lazy {
        applicationContext?.getBeanProvider(IJwtCustomizer::class.java)?.orderedStream()?.toList() ?: listOf()
    }

    override fun customize(context: JwtEncodingContext?) {
        if(context != null) {
            customizers.forEach {
                it.customizeToken(context)
            }
        }
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }
}