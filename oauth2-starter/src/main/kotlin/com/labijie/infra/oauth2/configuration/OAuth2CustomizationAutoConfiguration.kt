package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.DefaultAuthenticationProvider
import com.labijie.infra.oauth2.DefaultUserService
import com.labijie.infra.oauth2.IClientDetailsServiceFactory
import com.labijie.infra.oauth2.IIdentityService
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 * 用户必须实现的依赖
 */

@AutoConfigureBefore(UserDetailsServiceAutoConfiguration::class)
@ConditionalOnBean(AuthorizationEndpoint::class)
@Configuration
class OAuth2CustomizationAutoConfiguration(
        @JvmField private val identityService: IIdentityService) {

    @Configuration
    protected class OAuth2PasswordEncoderConfiguration {
        @Bean
        @ConditionalOnMissingBean(PasswordEncoder::class)
        fun encoder(): BCryptPasswordEncoder {
            return BCryptPasswordEncoder()
        }
    }

    @Configuration
    protected class AuthenticationProviderAutoConfiguration {
        @Primary
        @Bean
        fun defaultAuthenticationProvider(passwordEncoder: PasswordEncoder, userDetailService: DefaultUserService): DefaultAuthenticationProvider {
            return DefaultAuthenticationProvider(
                userDetailService,
                passwordEncoder
            )
        }
    }

    @Bean
    fun userDetailService(): DefaultUserService {
        return DefaultUserService(identityService)
    }

    @Primary
    @Bean
    fun defaultClientDetailsService(clientDetailsServiceFactory: IClientDetailsServiceFactory): ClientDetailsService {
        return clientDetailsServiceFactory.createClientDetailsService()
    }

    @Bean
    fun defaultOAuth2RequestFactory(clientDetailsService: ClientDetailsService): DefaultOAuth2RequestFactory {
        return DefaultOAuth2RequestFactory(clientDetailsService)
    }


}
