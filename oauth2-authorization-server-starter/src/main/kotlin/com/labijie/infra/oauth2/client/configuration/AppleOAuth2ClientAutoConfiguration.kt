package com.labijie.infra.oauth2.client.configuration

import com.labijie.infra.oauth2.client.IOidcLoginHandler
import com.labijie.infra.oauth2.client.IOpenIDConnectProvider
import com.labijie.infra.oauth2.client.IOpenIDConnectService
import com.labijie.infra.oauth2.client.OpenIDConnectService
import com.labijie.infra.oauth2.client.apple.AppleAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.apple.AppleOAuth2UserService
import com.labijie.infra.oauth2.mvc.OAuth2ClientLoginController
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.web.client.RestClient

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AppleOAuth2ClientRegistrationProperties::class, InfraOAuth2ClientProperties::class)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE)
class AppleOAuth2ClientAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(OAuth2ClientProperties::class)
    @EnableConfigurationProperties(OAuth2ClientProperties::class)
    protected class Oauth2ClientPropertiesAutoConfiguration

    @Bean
    @ConditionalOnMissingBean(IOpenIDConnectService::class)
    fun openIdTokenService(
        oauth2ClientProperties: OAuth2ClientProperties,
        infraOAuth2ClientProperties: InfraOAuth2ClientProperties,
        restClientBuilder: RestClient.Builder,
        providers: ObjectProvider<IOpenIDConnectProvider>
    ): IOpenIDConnectService
    {
        val svc = OpenIDConnectService(oauth2ClientProperties.provider, infraOAuth2ClientProperties, restClientBuilder).apply {
            providers.orderedStream().forEach {
                if(!this.hasProvider(it.providerName)) {
                    this.addProvider(it)
                }
            }
        }
        return svc
    }

    @Bean
    fun appleAuthorizationCodeTokenResponseClient(
        oauth2ClientProperties: OAuth2ClientProperties,
        properties: AppleOAuth2ClientRegistrationProperties): AppleAuthorizationCodeTokenResponseClient
    {
        return AppleAuthorizationCodeTokenResponseClient(oauth2ClientProperties, properties)
    }

    @Bean
    fun appleOAuth2UserService(
        oauth2ClientProperties: OAuth2ClientProperties,
        openIdTokenService: IOpenIDConnectService): AppleOAuth2UserService
    {
        return AppleOAuth2UserService(oauth2ClientProperties, openIdTokenService)
    }


    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    fun oidcLoginController(
        @Autowired(required = false) registeredClientRepository: RegisteredClientRepository?,
        infraOAuth2ClientProperties: InfraOAuth2ClientProperties,
        openIdTokenService: IOpenIDConnectService,
        @Autowired(required = false) oidcLoginHandler: IOidcLoginHandler?
    ): OAuth2ClientLoginController {
        return OAuth2ClientLoginController(registeredClientRepository, infraOAuth2ClientProperties, oidcLoginHandler, openIdTokenService)
    }
}