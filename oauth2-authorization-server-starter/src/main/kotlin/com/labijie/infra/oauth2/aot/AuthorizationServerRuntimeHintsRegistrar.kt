package com.labijie.infra.oauth2.aot

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationToken
import com.labijie.infra.oauth2.StandardOidcUser
import com.labijie.infra.oauth2.StandardOidcUserInfo
import com.labijie.infra.oauth2.client.configuration.InfraOAuth2ClientProperties
import com.labijie.infra.oauth2.client.configuration.OAuth2ClientOidcLoginProperties
import com.labijie.infra.oauth2.configuration.AuthorizationServiceProperties
import com.labijie.infra.oauth2.configuration.DefaultClientProperties
import com.labijie.infra.oauth2.configuration.JwtSettings
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.configuration.TokenProperties
import com.labijie.infra.oauth2.filter.ClientRequired
import com.labijie.infra.oauth2.mvc.CheckTokenController
import com.labijie.infra.oauth2.mvc.OAuth2ClientLoginController
import com.labijie.infra.oauth2.mvc.OidcLoginResult
import com.labijie.infra.oauth2.mvc.OidcLoginResultResponse
import com.labijie.infra.oauth2.serialization.jackson.*
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.TypeReference
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import java.security.Principal
import kotlin.jvm.java


class AuthorizationServerRuntimeHintsRegistrar : RuntimeHintsRegistrar {

    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {

        hints.reflection().registerType(TypeReference.of("org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"))
        hints.reflection().registerType(TypeReference.of("com.labijie.caching.ICacheManager"))
        hints.reflection().registerType(TypeReference.of("kotlinx.serialization.KSerializer"))
        hints.reflection().registerType(TypeReference.of("com.labijie.caching.redis.configuration.RedisCachingAutoConfiguration"))

        hints.reflection().registerTypes(
            listOf(
                TypeReference.of(UserPlainObject::class.java),
                TypeReference.of(AuthorizationPlainObject::class.java),
                TypeReference.of(TokenPlainObject::class.java),
                TypeReference.of(AccessTokenPlainObject::class.java),
                TypeReference.of(SimpleTwoFactorUserDetails::class.java),
                TypeReference.of(ResourceOwnerPasswordAuthenticationToken::class.java),
                TypeReference.of(ClientRequired::class.java),
                TypeReference.of(ITwoFactorUserDetails::class.java),
                TypeReference.of(StandardOidcUser::class.java),
                TypeReference.of(StandardOidcUserInfo::class.java),
                TypeReference.of(OAuth2ClientOidcLoginProperties::class.java),
            )
        ) {
            it.withMembers(*MemberCategory.entries.toTypedArray())
        }

        hints.reflection().registerType(IOAuthErrorWriter::class.java)
        hints.reflection().registerType(OAuth2AuthorizationCode::class.java)
        hints.reflection().registerType(IPrincipalResolver::class.java)
        hints.reflection().registerType(OAuth2AccessToken::class.java)
        hints.reflection().registerType(OidcIdToken::class.java)
        hints.reflection().registerType(Principal::class.java)
        hints.reflection().registerType(InfraOAuth2ClientProperties::class.java)
        hints.reflection().registerType(OAuth2ServerAutoConfiguration::class.java)

        //mvc
        hints.reflection().registerType(CheckTokenController::class.java)
        hints.reflection().registerType(OAuth2ClientLoginController::class.java)

        listOf(
            AccessToken::class.java,
            OAuth2AuthorizationResponseType::class.java,
            AuthorizationGrantType::class.java,
            AccessTokenSerializer::class.java,
            AccessTokenDeserializer::class.java,
            OAuth2AuthorizationResponseTypeSerializer::class.java,
            OAuth2AuthorizationResponseTypeDeserializer::class.java,
            AuthorizationGrantTypeSerializer::class.java,
            AuthorizationGrantTypeDeserializer::class.java,
            //nested configuration
            AuthorizationServiceProperties::class.java,
            DefaultClientProperties::class.java,
            TokenProperties::class.java,
            JwtSettings::class.java
        ).forEach { clazz ->
            hints.reflection().registerType(clazz) {
                it.withMembers(MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS)
            }
        }
    }
}