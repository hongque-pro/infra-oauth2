package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.client.DelegatingAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.DelegatingOAuth2UserService
import com.labijie.infra.oauth2.client.IOAuth2LoginCustomizer
import com.labijie.infra.oauth2.client.web.HttpCookieOAuth2AuthorizationRequestRepository
import jakarta.servlet.http.HttpServletRequest
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.RequestMatcher


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2ServerAutoConfiguration::class)
class OAuth2ServerSecurityAutoConfiguration() {

    companion object {
        private val EMPTY_MATCHER: RequestMatcher = RequestMatcher { request: HttpServletRequest? -> false }
    }

    @Configuration(proxyBeanMethods = false)
    protected class OAuth2LoginAutoConfiguration(
        private val oauth2LoginCustomizers: ObjectProvider<IOAuth2LoginCustomizer>,
        @param: Autowired(required = false)
        private val clientRegistrationRepository: ClientRegistrationRepository? = null,
        @param: Autowired(required = false)
        private var oauth2AuthorizationRequestRepository: AuthorizationRequestRepository<OAuth2AuthorizationRequest>? = null
    ) : ApplicationContextAware {

        private lateinit var applicationContext: ApplicationContext

        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 2)
        fun oauth2ServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {

           http.securityMatcher(EMPTY_MATCHER)

            if (clientRegistrationRepository != null) {
                val requestRepository =
                    oauth2AuthorizationRequestRepository ?: HttpCookieOAuth2AuthorizationRequestRepository()
                http.oauth2Login {
                    it.tokenEndpoint { endpoint ->
                        endpoint.accessTokenResponseClient(DelegatingAuthorizationCodeTokenResponseClient().apply {
                            setApplicationContext(applicationContext)
                        })
                    }
                    it.authorizationEndpoint { endpoint ->
                        endpoint.authorizationRequestRepository(requestRepository)
                    }
                    it.userInfoEndpoint { endpoint ->
                        endpoint.userService(DelegatingOAuth2UserService().apply {
                            setApplicationContext(applicationContext)
                        })
                    }
                    oauth2LoginCustomizers.orderedStream().forEach {
                        customizer ->
                        customizer.customize(it)
                    }
                    //it.loginPage("${baseUrl}/oauth2/unauthorized")
                }
            }
            return http.build()
        }

        override fun setApplicationContext(applicationContext: ApplicationContext) {
            this.applicationContext = applicationContext
        }


        @ConditionalOnClass(name = ["org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"])
        @Configuration(proxyBeanMethods = false)
        protected class ActuatorSecurityFilterConfiguration() {
            @Bean
            @Order(SecurityProperties.BASIC_AUTH_ORDER - 1)
            fun defaultSecurityFilterChain(
                http: HttpSecurity
            ): SecurityFilterChain {

                http.securityMatcher(EndpointRequest.toAnyEndpoint())
                    .sessionManagement {
                        it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        it.disable()
                    }
                    .csrf {
                        it.disable()
                    }

                return http.build()
            }
        }
    }
}