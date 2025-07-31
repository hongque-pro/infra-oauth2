package com.labijie.infra.oauth2.client.configuration

import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.client.*
import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.labijie.infra.oauth2.client.extension.IOpenIDConnectProvider
import com.labijie.infra.oauth2.client.provider.apple.AppleAuthorizationCodeTokenResponseClient
import com.labijie.infra.oauth2.client.provider.apple.AppleOAuth2UserService
import com.labijie.infra.oauth2.mvc.OAuth2ClientLoginController
import com.labijie.infra.oauth2.service.IOAuth2ServerOidcTokenService
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.web.client.RestClient

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(InfraOidcUserConverterAutoConfiguration::class)
@EnableConfigurationProperties(AppleOAuth2ClientRegistrationProperties::class, InfraOAuth2ClientProperties::class)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE)
class InfraOAuth2ClientAutoConfiguration {

    //可能会丢失 OAuth2ClientProperties
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(OAuth2ClientProperties::class)
    @EnableConfigurationProperties(OAuth2ClientProperties::class)
    protected class Oauth2ClientPropertiesAutoConfiguration


    @Bean
    @ConditionalOnMissingBean(IOAuth2ClientProviderService::class)
    fun defaultOAuth2ClientProviderService(oauth2ClientProperties: OAuth2ClientProperties): DefaultOAuth2ClientProviderService {
        return DefaultOAuth2ClientProviderService(oauth2ClientProperties)
    }


    @Bean
    @ConditionalOnMissingBean(IOAuth2UserInfoLoader::class)
    fun defaultOAuth2UserInfoLoader(
        oidcUserConverters: ObjectProvider<IOidcUserConverter>,
        oauth2ClientProviderService: IOAuth2ClientProviderService
    ): DefaultOAuth2UserInfoLoader {
        return DefaultOAuth2UserInfoLoader(oauth2ClientProviderService, oidcUserConverters.orderedStream().toList())
    }

    @Bean
    @ConditionalOnMissingBean(IOpenIDConnectService::class)
    fun defaultOpenIDConnectService(
        oauth2UserInfoLoader: DefaultOAuth2UserInfoLoader,
        @Autowired(required = false)
        clientRegistrationRepository: ClientRegistrationRepository?,
        oauth2ClientProviderService: IOAuth2ClientProviderService,
        infraOAuth2ClientProperties: InfraOAuth2ClientProperties,
        restClientBuilder: RestClient.Builder,
        providers: ObjectProvider<IOpenIDConnectProvider>
    ): IOpenIDConnectService {

        val svc = DefaultOpenIDConnectService(
            clientRegistrationRepository,
            oauth2UserInfoLoader,
            oauth2ClientProviderService,
            infraOAuth2ClientProperties,
            restClientBuilder
        ).apply {
            providers.orderedStream().forEach {
                if (!this.hasProvider(it.providerName)) {
                    this.addProvider(it)
                }
            }
        }
        return svc
    }

    @Bean
    fun appleAuthorizationCodeTokenResponseClient(
        oauth2ClientProperties: OAuth2ClientProperties,
        properties: AppleOAuth2ClientRegistrationProperties
    ): AppleAuthorizationCodeTokenResponseClient {
        return AppleAuthorizationCodeTokenResponseClient(oauth2ClientProperties, properties)
    }

    @Bean
    fun appleOAuth2UserService(
        oauth2ClientProperties: OAuth2ClientProperties,
        openIdTokenService: IOpenIDConnectService
    ): AppleOAuth2UserService {
        return AppleOAuth2UserService(oauth2ClientProperties, openIdTokenService)
    }


    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    fun oidcLoginController(
        oauth2ClientProviderService: IOAuth2ClientProviderService,
        @Autowired(required = false) registeredClientRepository: RegisteredClientRepository?,
        infraOAuth2ClientProperties: InfraOAuth2ClientProperties,
        openIdTokenService: IOpenIDConnectService,
        signInHelper: TwoFactorSignInHelper,
        serverOidcTokenService: IOAuth2ServerOidcTokenService,
        @Autowired(required = false) oidcLoginHandler: IOidcLoginHandler?
    ): OAuth2ClientLoginController {
        return OAuth2ClientLoginController(
            serverOidcTokenService,
            oauth2ClientProviderService,
            signInHelper,
            registeredClientRepository,
            infraOAuth2ClientProperties,
            oidcLoginHandler,
            openIdTokenService
        )
    }
}