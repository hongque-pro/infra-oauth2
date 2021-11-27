package com.labijie.infra.oauth2.configuration

import com.labijie.caching.redis.RedisCacheManager
import com.labijie.infra.oauth2.NoopPasswordEncoder
import com.labijie.infra.oauth2.OAuth2AuthorizationSerializer
import com.labijie.infra.oauth2.TwoFactorJwtCustomizer
import com.labijie.infra.oauth2.resolver.PasswordPrincipalResolver
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
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

        val registeredClientRepository = if(properties.clientRepository.equals("memory", true) || jdbcTemplate == null) InMemoryRegisteredClientRepository(registeredClients) else
            JdbcRegisteredClientRepository(jdbcTemplate).apply {
                val mapper = RegisteredClientParametersMapper()
                mapper.setPasswordEncoder(NoopPasswordEncoder.INSTANCE)
                this.setRegisteredClientParametersMapper(mapper)
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

    @Bean
    fun oauth2AuthorizationSerializer(clientRepository: RegisteredClientRepository): OAuth2AuthorizationSerializer {
        RedisCacheManager
        return OAuth2AuthorizationSerializer(clientRepository)
    }
}