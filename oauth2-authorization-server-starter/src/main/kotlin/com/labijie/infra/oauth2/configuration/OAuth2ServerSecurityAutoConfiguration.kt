package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.IResourceServerHttpSecurityConfigurer
import com.labijie.infra.oauth2.client.DelegatingAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.DelegatingOAuth2UserService
import com.labijie.infra.oauth2.client.extension.IOAuth2LoginCustomizer
import com.labijie.infra.oauth2.client.web.HttpCookieOAuth2AuthorizationRequestRepository
import com.labijie.infra.oauth2.matcher.ControllerClassRequestMatcher
import com.labijie.infra.oauth2.mvc.CheckTokenController
import com.labijie.infra.oauth2.mvc.OAuth2ClientLoginController
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
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
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(OAuth2ServerAutoConfiguration::class)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE - 100)
class OAuth2ServerSecurityAutoConfiguration() : ApplicationContextAware {

    companion object {
        private const val RESOURCE_SERVER_AUTO_CONFIG_CLASS =
            "com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration"
    }


    private lateinit var applicationContext: ApplicationContext

    @Autowired
    private lateinit var requestMappingHandlerMapping: RequestMappingHandlerMapping

    private val controllerMatcher by lazy {
        ControllerClassRequestMatcher(
            requestMappingHandlerMapping,
            CheckTokenController::class.java,
            OAuth2ClientLoginController::class.java
        )
    }

    @Bean("oauth2ServerControllersFilterChain")
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun oauth2ServerControllersFilterChain(
        http: HttpSecurity
    ): SecurityFilterChain {

        return http
            .securityMatcher(controllerMatcher)
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

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }


    @Configuration(proxyBeanMethods = false)
    protected class OAuth2LoginAutoConfiguration(
        private val oauth2LoginCustomizers: ObjectProvider<IOAuth2LoginCustomizer>,
        @param: Autowired(required = false)
        private val clientRegistrationRepository: ClientRegistrationRepository? = null,
        @param: Autowired(required = false)
        private var oauth2AuthorizationRequestRepository: AuthorizationRequestRepository<OAuth2AuthorizationRequest>? = null
    ) : ApplicationContextAware, IResourceServerHttpSecurityConfigurer, InitializingBean {

        private lateinit var applicationContext: ApplicationContext


        private lateinit var authorizationCodeTokenResponseClient: DelegatingAuthorizationCodeTokenResponseClient
        private lateinit var oauth2UserService: DelegatingOAuth2UserService


        override fun afterPropertiesSet() {
            authorizationCodeTokenResponseClient = DelegatingAuthorizationCodeTokenResponseClient().apply {
                setApplicationContext(applicationContext)
            }
            oauth2UserService = DelegatingOAuth2UserService().apply {
                setApplicationContext(applicationContext)
            }
        }

//        @Bean
//        @ConditionalOnMissingBean(IOAuth2UserQueryService::class)
//        fun defaultOAuth2UserQueryService(
//            oauth2UserInfoLoader: IOAuth2UserInfoLoader
//        ): DefaultOAuth2UserQueryService {
//            return DefaultOAuth2UserQueryService(
//                oauth2UserInfoLoader,
//                authorizationCodeTokenResponseClient,
//                oauth2UserService
//            )
//        }


        override fun configure(http: HttpSecurity) {
            if (clientRegistrationRepository != null) {
                val requestRepository =
                    oauth2AuthorizationRequestRepository ?: HttpCookieOAuth2AuthorizationRequestRepository()
                http.oauth2Login {
                    it.tokenEndpoint { endpoint ->
                        endpoint.accessTokenResponseClient(authorizationCodeTokenResponseClient)
                    }
                    it.authorizationEndpoint { endpoint ->
                        endpoint.authorizationRequestRepository(requestRepository)
                    }
                    it.userInfoEndpoint { endpoint ->
                        endpoint.userService(oauth2UserService)
                    }
                    oauth2LoginCustomizers.orderedStream().forEach { customizer ->
                        customizer.customize(it)
                    }

                    it.loginPage("/oauth2/unauthorized").permitAll()
                }
            }
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

    }
}