package com.labijie.infra.oauth2.configuration

import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-24
 */
@Configuration
@AutoConfigureAfter(AuthenticationProvider::class)
class WebSecurityAutoConfiguration : WebSecurityConfigurerAdapter() {

    @Bean
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }
//    @Autowired-
//    fun configureGloble(
//            builder:AuthenticationManagerBuilder,
//            provider: AuthenticationProvider
//    ){
//        builder.authenticationProvider(provider)
//    }
}