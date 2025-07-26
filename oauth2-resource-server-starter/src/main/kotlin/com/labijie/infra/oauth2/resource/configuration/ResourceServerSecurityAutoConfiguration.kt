package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.IHttpSecurityConfigurer
import com.labijie.infra.oauth2.OAuth2ExceptionHandler
import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.OAuth2AuthenticationEntryPoint
import com.labijie.infra.oauth2.resource.component.CookieSupportedBearerTokenResolver
import com.labijie.infra.oauth2.resource.component.IOAuth2TokenCookieDecoder
import com.labijie.infra.oauth2.resource.component.RequestMatcherPostProcessor
import jakarta.annotation.security.PermitAll
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/26
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE)
class ResourceServerSecurityAutoConfiguration(
    @param: Autowired(required = false)
    private val cookieDecoder: IOAuth2TokenCookieDecoder?,
    private val resourceServerProperties: ResourceServerProperties,
    private val jwtDecoder: JwtDecoder,
    private val resourceConfigurers: ObjectProvider<IResourceAuthorizationConfigurer>
) : ApplicationContextAware {

    private lateinit var applicationContext: ApplicationContext

    private fun getPermitAllUrlsFromController(): Array<String> {
        val requestMappingHandlerMapping = applicationContext.getBean(RequestMappingHandlerMapping::class.java)
        val handlerMethodMap = requestMappingHandlerMapping.handlerMethods
        val urlList = mutableSetOf<String>()
        handlerMethodMap.forEach { (key, value) ->
            value.method.getDeclaredAnnotation(PermitAll::class.java)?.let { permitAll ->
                key.pathPatternsCondition?.patterns?.let { urls ->
                    urls.forEach {
                        urlList.add(it.patternString)
                    }
                }
            }
        }
        return urlList.toTypedArray()
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    fun resourceServerSecurityChain(http: HttpSecurity, configurers: ObjectProvider<IHttpSecurityConfigurer>): SecurityFilterChain {

        val baseUrl = resourceServerProperties.baseUrl.removeSuffix("/")

        http.csrf {
            it.disable()
        }
        http.httpBasic {
            it.disable()
        }

        http.sessionManagement {
            it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            it.disable()
        }

//            val notOAuth2Matcher = PathPatternRequestMatcher.withDefaults().matcher("/oauth2/**").let {
//                NegatedRequestMatcher(it)
//            }

        //http.cors(Customizer.withDefaults())
        val settings = http
            .authorizeHttpRequests { authorize ->
                authorize.requestMatchers(*getPermitAllUrlsFromController()).permitAll()
                authorize.withObjectPostProcessor(RequestMatcherPostProcessor)
                authorize.requestMatchers(HttpMethod.OPTIONS).permitAll()
                authorize.requestMatchers("${baseUrl}/oauth2/unauthorized").permitAll()
                resourceConfigurers.orderedStream().forEach {
                    it.configure(authorize)
                }
                authorize.anyRequest().authenticated()
            }

        configurers.orderedStream().forEach {
                configurer -> configurer.configure(settings)
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
            obj.authenticationEntryPoint(OAuth2AuthenticationEntryPoint(applicationContext))
        }
        settings.exceptionHandling {
            it.accessDeniedHandler(OAuth2ExceptionHandler.getInstance(this.applicationContext))
        }



        return settings.formLogin { it.disable() }.build()
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
