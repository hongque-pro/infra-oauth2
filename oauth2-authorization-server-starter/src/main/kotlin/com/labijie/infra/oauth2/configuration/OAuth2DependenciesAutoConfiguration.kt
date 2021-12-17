package com.labijie.infra.oauth2.configuration

import com.labijie.caching.ICacheManager
import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.TwoFactorJwtCustomizer
import com.labijie.infra.oauth2.filter.ClientDetailsArgumentResolver
import com.labijie.infra.oauth2.filter.ClientDetailsInterceptorAdapter
import com.labijie.infra.oauth2.resolver.PasswordPrincipalResolver
import com.labijie.infra.oauth2.serialization.kryo.OAuth2KryoCacheDataSerializerCustomizer
import com.labijie.infra.oauth2.service.CachingOAuth2AuthorizationService
import com.labijie.infra.utils.logger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import java.util.function.Consumer


@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2ServerProperties::class)
class OAuth2DependenciesAutoConfiguration: ApplicationContextAware {

    private lateinit var springContext: ApplicationContext

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(RegisteredClientRepository::class)
    protected class RegisteredClientRepositoryAutoConfiguration(private val properties: OAuth2ServerProperties) {

        @Bean
        @ConditionalOnMissingBean(RegisteredClientRepository::class)
        @ConditionalOnBean(JdbcTemplate::class)
        fun jdbcClientRepository(jdbcTemplate: JdbcTemplate): JdbcRegisteredClientRepository {
            return JdbcRegisteredClientRepository(jdbcTemplate).apply {
                val mapper = RegisteredClientParametersMapper()
                this.setRegisteredClientParametersMapper(mapper)
            }.apply {
                this.saveResourceOwnerPasswordClient(properties)
            }
        }

        @Bean
        @ConditionalOnMissingBean(RegisteredClientRepository::class)
        fun inMemoryClientRepository(): InMemoryRegisteredClientRepository {
            val client = passwordClientRegistration(properties)
            return InMemoryRegisteredClientRepository(client)
        }

        private fun getTokenSettings(properties: OAuth2ServerProperties): TokenSettings {

            val tokenSettingsBuilder: TokenSettings.Builder =
                TokenSettings.builder().accessTokenTimeToLive(properties.token.accessTokenExpiration)
                    .refreshTokenTimeToLive(properties.token.refreshTokenExpiration)
                    .reuseRefreshTokens(properties.token.reuseRefreshToken)
            return tokenSettingsBuilder.build()
        }

        private fun passwordClientRegistration(properties: OAuth2ServerProperties): RegisteredClient {
            val tokenSetting = getTokenSettings(properties)
            return RegisteredClient.withId(properties.defaultClient.clientId)
                .clientId(properties.defaultClient.clientId)
                .clientName("infra_default")
                .clientSecret(properties.defaultClient.secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(tokenSetting)
                .build()
        }

        private fun RegisteredClientRepository.saveResourceOwnerPasswordClient(
            properties: OAuth2ServerProperties
        ) {
            if(properties.defaultClient.enabled) {
                val passwordRegisteredClient = passwordClientRegistration(properties)
                val registeredClients = mutableListOf<RegisteredClient>()
                registeredClients.add(passwordRegisteredClient)

                registeredClients.forEach(Consumer { registeredClient: RegisteredClient? ->
                    val id = registeredClient!!.id
                    val clientId = registeredClient.clientId
                    val dbRegisteredClient = this.findById(id) ?: this.findByClientId(clientId)
                    if (dbRegisteredClient == null) {
                        this.save(registeredClient)

                        logger.info("Default client with client id '${properties.defaultClient.clientId}', secret '${properties.defaultClient.secret}' has been created.")
                    }
                })

            }
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
        val encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder() as DelegatingPasswordEncoder
        return encoder.apply {
            this.setDefaultPasswordEncoderForMatches(BCryptPasswordEncoder())
        }
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
    @ConditionalOnMissingBean(OAuth2ServerProperties::class)
    fun providerSettings(serverProperties: OAuth2ServerProperties): ProviderSettings? {
        return ProviderSettings.builder()
            .authorizationEndpoint("/oauth/authorize")
            .tokenEndpoint("/oauth/token")
            .jwkSetEndpoint(Constants.DEFAULT_JWK_SET_ENDPOINT_PATH)
            .tokenRevocationEndpoint("/oauth/revoke")
            .tokenIntrospectionEndpoint(Constants.DEFAULT_JWS_INTROSPECT_ENDPOINT_PATH)
            .oidcClientRegistrationEndpoint("/connect/register")
            .issuer(serverProperties.issuer)
            .build()
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizationService::class)
    fun oauth2AuthorizationService(properties: OAuth2ServerProperties) : OAuth2AuthorizationService {
        val svc = when (properties.authorizationService) {
            "caching" -> {
                val cache = springContext.getBeanProvider(ICacheManager::class.java).firstOrNull()
                if (cache != null) {
                    CachingOAuth2AuthorizationService(cache)
                } else {
                    val msg = StringBuilder()
                        .appendLine("OAuth2 authorization service configured as 'caching', but ICacheManager bean missed, add one of follow packages to fix it:")
                        .appendLine("com.labijie:caching-kotlin-core-starter")
                        .appendLine("com.labijie:caching-kotlin-redis-starter")
                        .appendLine("Now, InMemoryOAuth2AuthorizationService will be used.")
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
                        .toString()
                    logger.warn(msg)
                    null
                }
            }
            else -> InMemoryOAuth2AuthorizationService()
        }
        return svc ?: InMemoryOAuth2AuthorizationService()
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        springContext = applicationContext
    }
}