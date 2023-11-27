package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorExpressionRoot
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.TypeHint

/**
 * @author Anders Xiao
 * @date 2023-11-27
 */

internal class OAuth2SecurityRuntimeHints : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        hints.reflection()
            .registerType(
                OAuth2TwoFactorExpressionRoot::class.java
            ) { builder: TypeHint.Builder ->
                builder
                    .withMembers(MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.DECLARED_FIELDS)
            }
    }
}
