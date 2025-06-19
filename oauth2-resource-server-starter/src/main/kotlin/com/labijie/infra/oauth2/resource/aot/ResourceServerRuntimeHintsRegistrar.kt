package com.labijie.infra.oauth2.resource.aot

import com.labijie.infra.oauth2.resource.configuration.ResourceServerAutoConfiguration
import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorExpressionRoot
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.TypeHint
import org.springframework.aot.hint.TypeReference
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager


class ResourceServerRuntimeHintsRegistrar : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        hints.reflection().registerTypes(
            listOf(
                TypeReference.of(RequestMatcherDelegatingAuthorizationManager::class.java)
            )
        ) {
            it.withMembers(*MemberCategory.entries.toTypedArray())
        }

        hints.reflection().registerType(ResourceServerAutoConfiguration::class.java)
        hints.reflection().registerType(ResourceServerAutoConfiguration::class.java)

        hints.reflection()
            .registerType(
                OAuth2TwoFactorExpressionRoot::class.java
            ) { builder: TypeHint.Builder ->
                builder
                    .withMembers(MemberCategory.INVOKE_PUBLIC_METHODS, MemberCategory.PUBLIC_FIELDS)
            }
    }
}