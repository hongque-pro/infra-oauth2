package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.OAuth2ResourceServerRunner
import com.labijie.infra.oauth2.security.OAuth2TwoFactorSecurityExpressionHandler
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
@Order(Int.MAX_VALUE)
@Configuration
@ConditionalOnBean(ResourceServerConfiguration::class)
class OAuth2ResourceServerAutoConfiguration: ResourceServerConfigurerAdapter(){

    @Bean
    fun oauth2ResourceServerRunner() = OAuth2ResourceServerRunner()

    override fun configure(resources: ResourceServerSecurityConfigurer) {
        resources.expressionHandler(OAuth2TwoFactorSecurityExpressionHandler)
    }

    override fun configure(http: HttpSecurity?) {

    }

}