package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.IResourceServerHttpSecurityConfigurer
import com.labijie.infra.oauth2.IUnauthorizedController
import com.labijie.infra.oauth2.OAuth2Constants.ENDPOINT_CHECK_TOKEN
import com.labijie.infra.oauth2.OAuth2Constants.OIDC_LOGIN_PATTERN
import com.labijie.infra.oauth2.OAuth2Constants.UNAUTHORIZED_ENDPOINT
import com.labijie.infra.oauth2.client.DelegatingAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.DelegatingOAuth2UserService
import com.labijie.infra.oauth2.client.extension.IOAuth2LoginCustomizer
import com.labijie.infra.oauth2.client.web.HttpCookieOAuth2AuthorizationRequestRepository
import com.labijie.infra.oauth2.mvc.AuthServerUnauthorizedController
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandlerImpl
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2ServerAutoConfiguration::class)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE - 100)
class OAuth2ServerSecurityAutoConfiguration() {

    companion object {
        private const val RESOURCE_SERVER_AUTO_CONFIG_CLASS =
            "com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration"
    }

    @Bean("oauth2ServerPermitAllFilterChain")
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun oauth2ServerPermitAllFilterChain(http: HttpSecurity): SecurityFilterChain {

        val checkPointerMatcher = PathPatternRequestMatcher.withDefaults().matcher(ENDPOINT_CHECK_TOKEN)
        val oidcLoginMatcher = PathPatternRequestMatcher.withDefaults().matcher(OIDC_LOGIN_PATTERN)

        val endpoints = OrRequestMatcher( checkPointerMatcher, oidcLoginMatcher)
        return http
            .securityMatcher(endpoints)
            .authorizeHttpRequests {
                it.anyRequest().permitAll()
            }
            .ignoreCSRF()
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                it.accessDeniedHandler(AccessDeniedHandlerImpl()) // 或自定义
            }
            .build()
    }


    @Configuration(proxyBeanMethods = false)
    protected class OAuth2LoginAutoConfiguration(
        private val oauth2LoginCustomizers: ObjectProvider<IOAuth2LoginCustomizer>,
        @param: Autowired(required = false)
        private val clientRegistrationRepository: ClientRegistrationRepository? = null,
        @param: Autowired(required = false)
        private var oauth2AuthorizationRequestRepository: AuthorizationRequestRepository<OAuth2AuthorizationRequest>? = null
    ) : ApplicationContextAware, IResourceServerHttpSecurityConfigurer {

        private lateinit var applicationContext: ApplicationContext



        override fun configure(http: HttpSecurity) {
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
                    oauth2LoginCustomizers.orderedStream().forEach { customizer ->
                        customizer.customize(it)
                    }

                    it.loginPage("/oauth2/unauthorized").permitAll()
                }
            }
        }



        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        @ConditionalOnMissingBean(IUnauthorizedController::class)
        fun authServerUnauthorizedController(): AuthServerUnauthorizedController {

            return AuthServerUnauthorizedController()
        }

        override fun setApplicationContext(applicationContext: ApplicationContext) {
            this.applicationContext = applicationContext
        }


        @ConditionalOnClass(name = ["org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"])
        @Configuration(proxyBeanMethods = false)
        protected class ActuatorSecurityFilterConfiguration() {

            @Bean
            @Order(SecurityProperties.BASIC_AUTH_ORDER - 1)
            fun actuatorSecurityFilterChain(
                http: HttpSecurity
            ): SecurityFilterChain {

                http
                    .securityMatcher(EndpointRequest.toAnyEndpoint())
                    .ignoreCSRF()
                return http.build()
            }
        }


        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE - 1)
        @ConditionalOnMissingClass(RESOURCE_SERVER_AUTO_CONFIG_CLASS)
        fun oauth2ServerSecurityFilterChain(
            serverProperties: OAuth2ServerProperties,
            http: HttpSecurity
        ): SecurityFilterChain {

            val settings = http
                .securityMatcher("/**")
                .authorizeHttpRequests { authorize ->
                    authorize.requestMatchers("/oauth2/unauthorized").permitAll()
                    authorize.anyRequest().authenticated()
                }

            configure(settings)
            return settings
                .applyCommonsPolicy(serverProperties.disableCsrf)
                .build()
        }
    }
}