package com.labijie.infra.oauth2.aot

import com.labijie.infra.oauth2.*
import com.labijie.infra.oauth2.authentication.ResourceOwnerPasswordAuthenticationToken
import com.labijie.infra.oauth2.configuration.OAuth2ServerAutoConfiguration
import com.labijie.infra.oauth2.filter.ClientRequired
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


class AuthorizationServerRuntimeHintsRegistrar : RuntimeHintsRegistrar {

    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {

        hints.reflection().registerType(TypeReference.of("org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"))
        hints.reflection().registerType(TypeReference.of("org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"))


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
        hints.reflection().registerType(OAuth2ServerAutoConfiguration::class.java)

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
        ).forEach { clazz ->
            hints.reflection().registerType(clazz) {
                it.withMembers(MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS)
            }
        }
    }
}