/**
 * @author Anders Xiao
 * @date 2025-06-18
 */
package com.labijie.infra.oauth2.aot

import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.configuration.IgnoreCsrfConfigure
import com.labijie.infra.oauth2.mvc.ErrorOptionalResponse
import com.labijie.infra.oauth2.mvc.OAuth2ServerCommonsController
import com.labijie.infra.oauth2.serialization.PlainOAuth2AuthorizationRequest
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.TypeReference
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.web.bind.annotation.RestController


class Oauth2CommonsRuntimeHintsRegistrar : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        hints.reflection().registerTypes(
            listOf(
                TypeReference.of(AccessToken::class.java),
                TypeReference.of(TwoFactorPrincipal::class.java),
                TypeReference.of(OAuth2AuthorizationRequest::class.java),
                TypeReference.of(PlainOAuth2AuthorizationRequest::class.java),
                TypeReference.of(ErrorOptionalResponse::class.java),
            )
        ) {
            it.withMembers(*MemberCategory.entries.toTypedArray())
        }
        hints.reflection().registerType(OAuth2Utils::class.java)
        hints.reflection().registerType(IgnoreCsrfConfigure::class.java)
        hints.reflection().registerType(OAuth2ServerCommonsController::class.java)
        hints.reflection().registerType(RestController::class.java)

        hints.resources().registerPattern("git-info/git.properties")
    }
}