package com.labijie.infra.oauth2.client.configuration

import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientAutoConfiguration
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/28
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureBefore(OAuth2ClientAutoConfiguration::class)
@ConditionalOnMissingBean(ClientRegistrationRepository::class)
@EnableConfigurationProperties(OAuth2ClientProperties::class)
class EmptyAllowOAuth2ClientRepositoryAutoConfiguration {

    @Bean
    fun clientRegistrationRepository(properties: OAuth2ClientProperties?): ClientRegistrationRepository {
        val registrations: MutableList<ClientRegistration?> = ArrayList(
            OAuth2ClientPropertiesMapper(properties).asClientRegistrations().values
        )
        if(registrations.isEmpty()) {
            return EmptyClientRegistrationRepository()
        }
        return InMemoryClientRegistrationRepository(registrations)
    }

    class EmptyClientRegistrationRepository : ClientRegistrationRepository, Iterable<ClientRegistration> {
        override fun findByRegistrationId(registrationId: String?): ClientRegistration? {
            return null
        }

        override fun iterator(): Iterator<ClientRegistration> {
            return emptyList<ClientRegistration>().iterator()
        }

    }
}