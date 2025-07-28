package com.labijie.infra.oauth2.configuration

import com.labijie.caching.ICacheManager
import com.labijie.infra.oauth2.IIdentityService
import com.labijie.infra.oauth2.OAuth2ServerUtils
import com.labijie.infra.oauth2.customizer.TwoFactorJwtCustomizer
import com.labijie.infra.oauth2.filter.ClientDetailsArgumentResolver
import com.labijie.infra.oauth2.filter.ClientDetailsInterceptorAdapter
import com.labijie.infra.oauth2.resolver.PasswordPrincipalResolver
import com.labijie.infra.oauth2.serialization.kryo.OAuth2KryoCacheDataSerializerCustomizer
import com.labijie.infra.oauth2.service.CachingOAuth2AuthorizationService
import com.labijie.infra.oauth2.service.DefaultUserService
import com.labijie.infra.oauth2.service.OAuth2Initializer
import com.labijie.infra.utils.ifNullOrBlank
import com.labijie.infra.utils.logger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.*
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import javax.sql.DataSource


@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(JdbcTemplateAutoConfiguration::class)
@AutoConfigureBefore(OAuth2AuthorizationServerConfiguration::class)
@EnableConfigurationProperties(OAuth2ServerProperties::class)
class OAuth2DependenciesAutoConfiguration : ApplicationContextAware {

    private lateinit var springContext: ApplicationContext

//    @Bean
//    @Order(Ordered.HIGHEST_PRECEDENCE)
//    @Throws(Exception::class)
//    fun overrideAuthorizationServerSecurityFilterChain(
//        http: HttpSecurity,
//        serverProperties: OAuth2ServerProperties): SecurityFilterChain {
//        // @formatter:off
//        val authorizationServerConfigurer =
//            OAuth2AuthorizationServerConfigurer.authorizationServer()
//        http
//            .securityMatcher(authorizationServerConfigurer.endpointsMatcher)
//            .applyCommonsPolicy(serverProperties.disableCsrf)
//
//        return http.build()
//    }


    @Bean
    @ConditionalOnMissingBean(UserDetailsService::class)
    @ConditionalOnBean(IIdentityService::class)
    fun defaultUserDetailService(identityService: IIdentityService): DefaultUserService {
        return DefaultUserService(identityService)
    }


    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(RegisteredClientRepository::class)
    protected class RegisteredClientRepositoryAutoConfiguration(private val properties: OAuth2ServerProperties) {

        @Bean
        @ConditionalOnMissingBean(RegisteredClientRepository::class)
        @ConditionalOnBean(JdbcTemplate::class)
        @ConditionalOnProperty(
            prefix = "infra.oauth2",
            name = ["client-repository"],
            havingValue = "jdbc",
            matchIfMissing = false
        )
        fun jdbcClientRepository(jdbcTemplate: JdbcTemplate): JdbcRegisteredClientRepository {
            return JdbcRegisteredClientRepository(jdbcTemplate)
        }

        @Bean
        @ConditionalOnMissingBean(RegisteredClientRepository::class)
        @ConditionalOnProperty(
            prefix = "infra.oauth2",
            name = ["client-repository"],
            havingValue = "memory",
            matchIfMissing = true
        )
        fun inMemoryClientRepository(): InMemoryRegisteredClientRepository {
            val client = OAuth2ServerUtils.createDefaultClientRegistration(properties)
            return InMemoryRegisteredClientRepository(client)
        }
    }

    @Bean
    fun twoFactorJwtCustomizer(): TwoFactorJwtCustomizer {
        return TwoFactorJwtCustomizer()
    }

    @Bean
    fun passwordPrincipalResolver(): PasswordPrincipalResolver {
        return PasswordPrincipalResolver()
    }


    @Bean
    @ConditionalOnMissingBean(PasswordEncoder::class)
    fun oauth2PasswordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }


    @Configuration
    @ConditionalOnClass(name = ["com.labijie.caching.redis.configuration.RedisCachingAutoConfiguration"])
    class OAuth2KryoConfiguration {
        @Bean
        fun oauth2KryoCacheDataSerializerCustomizer(): OAuth2KryoCacheDataSerializerCustomizer =
            OAuth2KryoCacheDataSerializerCustomizer()
    }


    @Configuration
    @ConditionalOnBean(RegisteredClientRepository::class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    protected class ClientDetailsArgumentResolverAutoConfiguration : WebMvcConfigurer {

        @Autowired
        private lateinit var registeredClientRepository: RegisteredClientRepository

        override fun addArgumentResolvers(resolvers: MutableList<HandlerMethodArgumentResolver>) {
            resolvers.add(ClientDetailsArgumentResolver(registeredClientRepository))
        }

        override fun addInterceptors(registry: InterceptorRegistry) {
            registry.addInterceptor(ClientDetailsInterceptorAdapter(registeredClientRepository))
        }
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationServerSettings::class)
    fun authorizationServerSettings(
        properties: OAuth2ServerProperties,
        environment: Environment
    ): AuthorizationServerSettings {

        val issuser = environment.getProperty("spring.security.oauth2.authorizationserver.issuer")

        return AuthorizationServerSettings.builder().let { builder ->
            issuser?.let {
                builder.issuer(it)
            } ?: builder
        }
            .build()
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(OAuth2AuthorizationService::class)
    @ConditionalOnClass(name = ["com.labijie.caching.ICacheManager"])
    @ConditionalOnProperty(
        name = ["infra.oauth2.authorization-server.authorization-service.provider"],
        havingValue = "caching",
        matchIfMissing = true
    )
    class CachingAuthorizationServiceAutoConfiguration {
        @Bean
        fun cachingOAuth2AuthorizationService(
            cacheManager: ICacheManager,
            properties: OAuth2ServerProperties
        ): CachingOAuth2AuthorizationService {
            logger.info("Caching oauth2 authorization service has been used, cache region: ${properties.authorizationService.cachingRegion.ifNullOrBlank { "default" }}")
            return CachingOAuth2AuthorizationService(
                cacheManager,
                properties.authorizationService.cachingRegion
            )
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(OAuth2AuthorizationService::class)
    @ConditionalOnProperty(
        name = ["infra.oauth2.authorization-server.authorization-service.provider"],
        havingValue = "jdbc",
        matchIfMissing = true
    )
    class JdbcAuthorizationServiceAutoConfiguration {
        @Bean
        @ConditionalOnBean(JdbcTemplate::class)
        fun cachingOAuth2AuthorizationService(
            jdbcTemplate: JdbcTemplate,
            registeredClientRepository: RegisteredClientRepository,
            properties: OAuth2ServerProperties
        ): JdbcOAuth2AuthorizationService {
            return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
        }
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2Initializer::class)
    @ConditionalOnBean(DataSource::class)
    fun oauth2Initializer(dataSource: DataSource, properties: OAuth2ServerProperties): OAuth2Initializer {
        return OAuth2Initializer(dataSource, properties)
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        springContext = applicationContext
    }
}