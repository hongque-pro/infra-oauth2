package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.IResourceServerHttpSecurityConfigurer
import com.labijie.infra.oauth2.OAuth2ExceptionHandler
import com.labijie.infra.oauth2.buildMatchers
import com.labijie.infra.oauth2.configuration.OAuth2ServerCommonsProperties
import com.labijie.infra.oauth2.configuration.applyCommonsPolicy
import com.labijie.infra.oauth2.resource.OAuth2AuthenticationEntryPoint
import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.component.CookieSupportedBearerTokenResolver
import com.labijie.infra.oauth2.resource.component.IOAuth2TokenCookieDecoder
import com.labijie.infra.oauth2.resource.component.RequestMatcherPostProcessor
import jakarta.annotation.security.PermitAll
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/26
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(ResourceServerAutoConfiguration::class)
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration::class)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE)
class ResourceServerSecurityAutoConfiguration(
    @param: Autowired(required = false)
    private val cookieDecoder: IOAuth2TokenCookieDecoder?,
    private val resourceServerProperties: ResourceServerProperties,
    private val jwtDecoder: JwtDecoder,
    private val resourceConfigurers: ObjectProvider<IResourceAuthorizationConfigurer>
) : ApplicationContextAware {

    private lateinit var applicationContext: ApplicationContext

    private fun getPermitAllMatcher(): List<RequestMatcher> {
        val requestMappingHandlerMapping = applicationContext.getBean(RequestMappingHandlerMapping::class.java)
        val handlerMethodMap = requestMappingHandlerMapping.handlerMethods
        return handlerMethodMap.flatMap { (key, value) ->
            if(value.method.getDeclaredAnnotation(PermitAll::class.java) != null ||
                value.method.declaringClass.getAnnotation(PermitAll::class.java) != null) {
                key.buildMatchers()
            }
            else {
                emptyList()
            }
        }
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    fun resourceServerSecurityChain(
        http: HttpSecurity,
        serverProperties: ResourceServerProperties,
        configurers: ObjectProvider<IResourceServerHttpSecurityConfigurer>,
        commonsProperties: OAuth2ServerCommonsProperties
    ): SecurityFilterChain {

        //http.cors(Customizer.withDefaults())
        val settings = http
            .securityMatcher("/**")
            .authorizeHttpRequests { authorize ->
                authorize.requestMatchers(HttpMethod.OPTIONS).permitAll()
                authorize.requestMatchers("/oauth2/unauthorized", "/error").permitAll()
                val permitAllMatchers = getPermitAllMatcher()
                if(permitAllMatchers.isNotEmpty()) {
                    authorize.requestMatchers(*permitAllMatchers.toTypedArray()).permitAll()
                }

                authorize.withObjectPostProcessor(RequestMatcherPostProcessor)

                resourceConfigurers.orderedStream().forEach {
                    it.configure(authorize)
                }
                authorize.anyRequest().authenticated()
            }


        settings.oauth2ResourceServer { obj ->
            obj.jwt {
                applyJwtConfiguration(it)
            }
            obj.bearerTokenResolver(CookieSupportedBearerTokenResolver(cookieDecoder).apply {
                this.setBearerTokenFromCookieName(resourceServerProperties.bearerTokenResolver.allowCookieName)
                this.setAllowUriQueryParameter(resourceServerProperties.bearerTokenResolver.allowUriQueryParameter)
                this.setAllowFormEncodedBodyParameter(resourceServerProperties.bearerTokenResolver.allowFormEncodedBodyParameter)
            })
            obj.authenticationEntryPoint(OAuth2AuthenticationEntryPoint())
        }
        settings.exceptionHandling {
            it.accessDeniedHandler(OAuth2ExceptionHandler)
        }

        configurers.orderedStream().forEach { configurer ->
            configurer.configure(settings)
        }


        return settings.formLogin {
            it.loginPage("/oauth2/unauthorized")
            it.permitAll()
            it.disable()
        }
        .applyCommonsPolicy(commonsProperties)
        .build()
    }

    fun applyJwtConfiguration(
        configurer: OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer
    ): OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer {
        configurer.decoder(jwtDecoder)

        return configurer
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }
}
