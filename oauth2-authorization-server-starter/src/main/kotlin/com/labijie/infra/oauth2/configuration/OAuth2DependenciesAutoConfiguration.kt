package com.labijie.infra.oauth2.configuration

import com.labijie.caching.redis.RedisCacheManager
import com.labijie.infra.oauth2.NoopPasswordEncoder
import com.labijie.infra.oauth2.TwoFactorJwtCustomizer
import com.labijie.infra.oauth2.filter.ClientDetailsArgumentResolver
import com.labijie.infra.oauth2.filter.ClientDetailsInterceptorAdapter
import com.labijie.infra.oauth2.resolver.PasswordPrincipalResolver
import com.labijie.infra.oauth2.serialization.kryo.OAuth2KryoCacheDataSerializerCustomizer
import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import java.util.function.Consumer


@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2ServerProperties::class)
class OAuth2DependenciesAutoConfiguration {


    @ConditionalOnMissingBean(RegisteredClientRepository::class)
    @Bean
    fun infraRegisteredClientRepository(
        properties: OAuth2ServerProperties,
        @Autowired(required = false)
        jdbcTemplate: JdbcTemplate?
    ): RegisteredClientRepository {

        val passwordRegisteredClient = passwordClientRegistration(properties)
        val registeredClients = mutableListOf<RegisteredClient>()
        registeredClients.add(passwordRegisteredClient)

        val registeredClientRepository = if(properties.clientRepository.equals("memory", true)) InMemoryRegisteredClientRepository(registeredClients) else {
            val template = jdbcTemplate ?: throw BeanCreationException("Client repository as configured as '${properties.clientRepository}', jdbc will be used, but JdbcTemplate bean is not found, use 'memory' repository or add spring-boot-starter-jdbc package.")

            JdbcRegisteredClientRepository(template).apply {
                val mapper = RegisteredClientParametersMapper()
                mapper.setPasswordEncoder(NoopPasswordEncoder.INSTANCE)
                this.setRegisteredClientParametersMapper(mapper)
            }
        }


        registeredClients.forEach(Consumer { registeredClient: RegisteredClient? ->
            val id = registeredClient!!.id
            val clientId = registeredClient.clientId
            var dbRegisteredClient = registeredClientRepository.findById(id)
            if (dbRegisteredClient == null) {
                dbRegisteredClient = registeredClientRepository.findByClientId(clientId)
            }
            if (dbRegisteredClient == null) {
                registeredClientRepository.save(registeredClient)
            }
        })
        return registeredClientRepository
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


    private fun getTokenSettings(properties: OAuth2ServerProperties): TokenSettings {

        val tokenSettingsBuilder: TokenSettings.Builder =
            TokenSettings.builder().accessTokenTimeToLive(properties.token.accessTokenExpiration)
                .refreshTokenTimeToLive(properties.token.refreshTokenExpiration)
                .reuseRefreshTokens(properties.token.reuseRefreshToken)
        return tokenSettingsBuilder.build()
    }

    @Bean
    fun twoFactorJwtCustomizer(): TwoFactorJwtCustomizer{
        return TwoFactorJwtCustomizer()
    }

    @Bean
    fun passwordPrincipalResolver(): PasswordPrincipalResolver{
        return PasswordPrincipalResolver()
    }


    @Configuration
    @ConditionalOnClass(name = ["com.labijie.caching.redis.RedisCacheManager"])
    class OAuth2KryoConfiguration {
        @Bean
        @ConditionalOnBean(RedisCacheManager::class)
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
}