package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.token.TwoFactorAuthenticationConverter
import org.springframework.boot.CommandLineRunner
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.core.token.TokenService
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter
import org.springframework.security.oauth2.provider.token.RemoteTokenServices

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-09
 */
class OAuth2ResourceServerRunner : CommandLineRunner, ApplicationContextAware {
    private lateinit var context: ApplicationContext

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        context = applicationContext
    }

    override fun run(vararg args: String?) {

        val services = this.context.getBeansOfType(RemoteTokenServices::class.java)
        if (!services.isNullOrEmpty()) {

            val accessTokenConverter = DefaultAccessTokenConverter().apply {
                this.setUserTokenConverter(TwoFactorAuthenticationConverter)
                this.setIncludeGrantType(true)
            }

            services.forEach { _, u ->
                u.setAccessTokenConverter(accessTokenConverter)
            }

        }
    }
}