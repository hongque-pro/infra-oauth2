package com.labijie.infra.oauth2.resource.aot

import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.configuration.BearerTokenResolverSettings
import com.labijie.infra.oauth2.resource.configuration.ResourceJwtSettings
import com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration
import com.labijie.infra.oauth2.resource.configuration.ResourceServerSecurityAutoConfiguration
import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorExpressionRoot
import org.springframework.aot.hint.*
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager


class ResourceServerRuntimeHintsRegistrar : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        hints.reflection().registerTypes(
            listOf(
                TypeReference.of(RequestMatcherDelegatingAuthorizationManager::class.java),
                TypeReference.of(ResourceJwtSettings::class.java),
                TypeReference.of(ResourceJwtSettings::class.java),
                TypeReference.of(BearerTokenResolverSettings::class.java),

                )
        ) {
            it.withMembers(*MemberCategory.entries.toTypedArray())
        }

        hints.reflection().registerType(ResourceServerAutoConfiguration::class.java)
        hints.resources().registerType(ResourceServerSecurityAutoConfiguration::class.java)
        hints.reflection().registerType(IResourceAuthorizationConfigurer::class.java)
        hints.reflection()
            .registerType(TypeReference.of("org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"))


        hints.reflection()
            .registerType(
                OAuth2TwoFactorExpressionRoot::class.java
            ) { builder: TypeHint.Builder ->
                builder
                    .withMembers(MemberCategory.INVOKE_PUBLIC_METHODS, MemberCategory.PUBLIC_FIELDS)
            }
    }
}