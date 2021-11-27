package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.service.DefaultUserService
import com.labijie.infra.oauth2.IIdentityService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.AdviceMode
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain


@Configuration(proxyBeanMethods = false)
@EnableGlobalMethodSecurity(
    prePostEnabled = true,
    order = 0,
    mode = AdviceMode.PROXY,
    proxyTargetClass = false
)
@EnableWebSecurity
@AutoConfigureAfter(OAuth2ServerAutoConfiguration::class)
class OAuth2SecurityAutoConfiguration {

    @Autowired
    private lateinit var identityService: IIdentityService

    @Configuration(proxyBeanMethods = false)
    protected class OAuth2PasswordEncoderConfiguration {

        @Bean
        @ConditionalOnMissingBean(PasswordEncoder::class)
        fun oauth2PasswordEncoder(): PasswordEncoder {
            val encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder() as DelegatingPasswordEncoder
            return encoder.apply {
                this.setDefaultPasswordEncoderForMatches(BCryptPasswordEncoder())
            }
        }
    }

    private fun getUserService(identityService: IIdentityService): DefaultUserService {
        return DefaultUserService(this.identityService)
    }

    @Autowired
    protected fun configureGlobal(builder: AuthenticationManagerBuilder) {
        builder
            .userDetailsService(this.getUserService(identityService)) // .passwordEncoder(passwordEncoder())
            .and()
            .eraseCredentials(true)
    }

    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http.authorizeRequests { authorizeRequests ->
            authorizeRequests.requestMatchers(EndpointRequest.toAnyEndpoint())
                .permitAll()
                .mvcMatchers(Constants.DEFAULT_JWK_SET_ENDPOINT_PATH, Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH)
                .permitAll()
                .anyRequest().permitAll()
            }
            //.formLogin(withDefaults())
            .csrf().disable()
            .headers().frameOptions().sameOrigin()
        return http.build()
    }

}