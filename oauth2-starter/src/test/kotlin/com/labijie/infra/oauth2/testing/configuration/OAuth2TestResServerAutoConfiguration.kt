package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.hasAttachedFiledValue
import com.labijie.infra.oauth2.testing.TestController
import com.labijie.infra.oauth2.testing.component.OAuth2TestingUtils
import com.labijie.infra.oauth2.twoFactorRequired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer
import kotlin.jvm.Throws

@Import(OAuth2TestServerAutoConfiguration::class)
class OAuth2TestResServerAutoConfiguration : ResourceServerConfigurerAdapter() {

    @Bean
    fun testController(): TestController {
        return TestController()
    }

    override fun configure(resources: ResourceServerSecurityConfigurer) {
        resources.resourceId(OAuth2TestingUtils.ResourceId)
    }

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http.requestMatchers().anyRequest()
                .and()
                .anonymous()
                .and()
                .authorizeRequests()
                .antMatchers("/test/2fac").twoFactorRequired()
                .antMatchers("/**").authenticated()
    }
}