package com.labijie.infra.oauth2.configuration

import com.labijie.caching.ICacheManager
import com.labijie.infra.oauth2.IIdentityService
import com.labijie.infra.oauth2.OAuth2ServerUtils
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.TwoFactorJwtCustomizer
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
import org.springframework.boot.autoconfigure.condition.*
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import javax.sql.DataSource


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(JdbcTemplateAutoConfiguration::class)
@EnableConfigurationProperties(OAuth2ServerProperties::class)
class OAuth2DependenciesAutoConfiguration: ApplicationContextAware {

    private lateinit var springContext: ApplicationContext

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
        @ConditionalOnProperty(prefix = "infra.oauth2", name = ["client-repository"], havingValue = "jdbc", matchIfMissing = false)
        fun jdbcClientRepository(jdbcTemplate: JdbcTemplate): JdbcRegisteredClientRepository {
            return JdbcRegisteredClientRepository(jdbcTemplate)
        }

        @Bean
        @ConditionalOnMissingBean(RegisteredClientRepository::class)
        @ConditionalOnProperty(prefix = "infra.oauth2", name = ["client-repository"], havingValue = "memory", matchIfMissing = true)
        fun inMemoryClientRepository(): InMemoryRegisteredClientRepository {
            val client = OAuth2ServerUtils.createDefaultClientRegistration(properties)
            return InMemoryRegisteredClientRepository(client)
        }
    }

    @Bean
    fun twoFactorJwtCustomizer(): TwoFactorJwtCustomizer{
        return TwoFactorJwtCustomizer()
    }

    @Bean
    fun passwordPrincipalResolver(): PasswordPrincipalResolver{
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
        fun oauth2KryoCacheDataSerializerCustomizer(): OAuth2KryoCacheDataSerializerCustomizer = OAuth2KryoCacheDataSerializerCustomizer()
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
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }


    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizationService::class)
    fun oauth2AuthorizationService(properties: OAuth2ServerProperties) : OAuth2AuthorizationService {
        val svc = when (properties.authorizationService.provider) {
            "caching" -> {
                val cache = springContext.getBeanProvider(ICacheManager::class.java).firstOrNull()
                if (cache != null) {
                    logger.info("Caching oauth2 authorization service has been used, cache region: ${properties.authorizationService.cachingRegion.ifNullOrBlank { "default" }}")
                    CachingOAuth2AuthorizationService(cache)
                } else {
                    val msg = StringBuilder()
                        .appendLine("OAuth2 authorization service configured as 'caching'," +
                                "but ICacheManager bean missed, add one of follow packages to fix it:")
                        .appendLine("com.labijie:caching-kotlin-core-starter")
                        .appendLine("com.labijie:caching-kotlin-redis-starter")
                        .appendLine("Now, InMemoryOAuth2AuthorizationService will be used.")
                        .appendLine()
                        .appendLine("OAuth2 authorization service fallback to in memory provider.")
                        .toString()
                    logger.warn(msg)
                    null
                }
            }
            "jdbc" -> {
                val jdbcTemplate = springContext.getBeanProvider(JdbcTemplate::class.java).firstOrNull()
                if (jdbcTemplate != null) {
                    val clientRepo = springContext.getBean(RegisteredClientRepository::class.java)
                    JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepo)
                } else {
                    val msg = StringBuilder()
                        .appendLine("OAuth2 authorization service configured as 'jdbc', but JdbcTemplate bean missed, add follow package to fix it:")
                        .appendLine("org.springframework.boot:spring-boot-starter-jdbc")
                        .appendLine("Now, InMemoryOAuth2AuthorizationService will be used.")
                        .appendLine()
                        .appendLine("OAuth2 authorization service fallback to in memory provider.")
                        .toString()
                    logger.warn(msg)
                    null
                }
            }
            else -> InMemoryOAuth2AuthorizationService()
        }
        return svc ?: InMemoryOAuth2AuthorizationService()
    }


    @Bean
    @ConditionalOnMissingBean(OAuth2Initializer::class)
    @ConditionalOnBean(DataSource::class)
    fun oauth2Initializer(dataSource: DataSource, properties: OAuth2ServerProperties) : OAuth2Initializer {
        return OAuth2Initializer(dataSource, properties)
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        springContext = applicationContext
    }
}