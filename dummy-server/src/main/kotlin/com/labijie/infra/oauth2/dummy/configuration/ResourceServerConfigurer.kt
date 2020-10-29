package com.labijie.infra.oauth2.dummy.configuration

import com.labijie.infra.oauth2.hasAttachedFiledValue
import com.labijie.infra.oauth2.twoFactorRequired
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer
import kotlin.jvm.Throws


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */

@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
class ResourceServerConfigurer : ResourceServerConfigurerAdapter() {

    override fun configure(resources: ResourceServerSecurityConfigurer) {
        resources.resourceId("auth")
    }

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http.requestMatchers().anyRequest()
                .and()
                .anonymous()
                .and()
                .authorizeRequests()
                .antMatchers("/attached").hasAttachedFiledValue("aaa", "bbb")
                .antMatchers("/2f").twoFactorRequired()
                .antMatchers("/login").authenticated()
                .antMatchers("/**").authenticated()
    }
}