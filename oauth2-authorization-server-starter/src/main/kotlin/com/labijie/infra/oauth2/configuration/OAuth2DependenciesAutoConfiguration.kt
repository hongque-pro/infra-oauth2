package com.labijie.infra.oauth2.configuration

import com.labijie.caching.ICacheManager
import com.labijie.infra.oauth2.IIdentityService
import com.labijie.infra.oauth2.OAuth2ServerUtils
import com.labijie.infra.oauth2.annotation.ConditionalOnSecurityEnabled
import com.labijie.infra.oauth2.component.DefaultOAuth2ServerRSAKeyPair
import com.labijie.infra.oauth2.component.IOAuth2ServerRSAKeyPair
import com.labijie.infra.oauth2.component.IOAuth2ServerSecretsStore
import com.labijie.infra.oauth2.customizer.TwoFactorJwtCustomizer
import com.labijie.infra.oauth2.filter.ClientDetailsArgumentResolver
import com.labijie.infra.oauth2.filter.ClientDetailsInterceptorAdapter
import com.labijie.infra.oauth2.resolver.PasswordPrincipalResolver
import com.labijie.infra.oauth2.service.*
import com.labijie.infra.utils.ifNullOrBlank
import com.labijie.infra.utils.logger
import org.slf4j.LoggerFactory
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
import org.springframework.core.env.Environment
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import javax.sql.DataSource


@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(JdbcTemplateAutoConfiguration::class)
@AutoConfigureBefore(OAuth2AuthorizationServerConfiguration::class)
@EnableConfigurationProperties(OAuth2ServerProperties::class)
@ConditionalOnSecurityEnabled
class OAuth2DependenciesAutoConfiguration : ApplicationContextAware {

    private lateinit var springContext: ApplicationContext


    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger("com.labijie.infra.oauth2.configuration.OAuth2DependenciesAutoConfiguration")
        }
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationServerSettings::class)
    fun authorizationServerSettings(
        properties: OAuth2ServerProperties,
        environment: Environment
    ): AuthorizationServerSettings {

        val issuer = environment.getProperty("spring.security.oauth2.authorizationserver.issuer")
            .ifNullOrBlank { OAuth2ServerUtils.DEFAULT_ISSUER }
        return AuthorizationServerSettings.builder()
            .issuer(issuer)
            .build()
    }


    @Bean
    @ConditionalOnMissingBean(IOAuth2ServerRSAKeyPair::class)
    fun oauth2ServerRSAKeyPair(
        properties: OAuth2ServerProperties,
        @Autowired(required = false) secretsStore: IOAuth2ServerSecretsStore?
    ): IOAuth2ServerRSAKeyPair {
        return DefaultOAuth2ServerRSAKeyPair(properties, secretsStore)
    }


    @Bean
    @ConditionalOnMissingBean(IOAuth2ServerOidcTokenService::class)
    fun defaultServerOidcTokenService(
        serverSettings: AuthorizationServerSettings,
        serverRSAKeyPair: IOAuth2ServerRSAKeyPair
    ): DefaultOAuth2ServerOidcTokenService {

        return DefaultOAuth2ServerOidcTokenService(serverRSAKeyPair, serverSettings)
    }

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
            prefix = "infra.oauth2.authorization-server.server-client",
            name = ["repository"],
            havingValue = "jdbc",
            matchIfMissing = false
        )
        fun jdbcClientRepository(jdbcTemplate: JdbcTemplate): JdbcRegisteredClientRepository {
            return JdbcRegisteredClientRepository(jdbcTemplate)
        }

        @Bean
        @ConditionalOnMissingBean(RegisteredClientRepository::class)
        @ConditionalOnProperty(
            prefix = "infra.oauth2.authorization-server.server-client",
            name = ["repository"],
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
    @AutoConfigureAfter(RegisteredClientRepositoryAutoConfiguration::class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    protected class ClientDetailsArgumentResolverAutoConfiguration(private val registeredClientRepository: RegisteredClientRepository) : WebMvcConfigurer {

        override fun addArgumentResolvers(resolvers: MutableList<HandlerMethodArgumentResolver>) {
            resolvers.add(ClientDetailsArgumentResolver(registeredClientRepository))
        }

        override fun addInterceptors(registry: InterceptorRegistry) {
            registry.addInterceptor(ClientDetailsInterceptorAdapter(registeredClientRepository))
        }
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