/**
 * @author Anders Xiao
 * @date 2025-06-18
 */
package com.labijie.infra.oauth2.aot

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.configuration.IgnoreCsrfConfigure
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.TypeReference


class Oauth2CommonsRuntimeHintsRegistrar : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        hints.reflection().registerTypes(
            listOf(
                TypeReference.of(AccessToken::class.java),
                TypeReference.of(TwoFactorPrincipal::class.java),
            )
        ) {
            it.withMembers(*MemberCategory.entries.toTypedArray())
        }
        hints.reflection().registerType(OAuth2Utils::class.java)
        hints.reflection().registerType(IgnoreCsrfConfigure::class.java)

        hints.resources().registerPattern("git-info/git.properties")
    }
}