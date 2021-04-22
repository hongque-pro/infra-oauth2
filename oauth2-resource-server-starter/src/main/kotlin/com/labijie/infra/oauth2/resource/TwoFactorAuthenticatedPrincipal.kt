package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.TwoFactorPrincipal
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimAccessor
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames
import java.io.Serializable

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 19:19
 * @Description:
 */

class TwoFactorAuthenticatedPrincipal(private val delegate: TwoFactorPrincipal) : OAuth2AuthenticatedPrincipal, OAuth2IntrospectionClaimAccessor, Serializable {
    override fun getName(): String = delegate.userName

    fun getTwoFactorPrincipal(): TwoFactorPrincipal {
        return this.delegate
    }

    private val mergedAttributes by lazy {
        val map = mutableMapOf<String, Any>()
        map[OAuth2IntrospectionClaimNames.ACTIVE] = true
        map[Constants.CLAIM_USER_ID] = delegate.userId
        map[OAuth2IntrospectionClaimNames.USERNAME] = delegate.userName

        if (delegate.attachedFields.containsKey(Constants.CLAIM_EXP)) {
            map[OAuth2IntrospectionClaimNames.EXPIRES_AT] = delegate.attachedFields.getOrDefault(Constants.CLAIM_EXP, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_AUD)) {
            map[OAuth2IntrospectionClaimNames.AUDIENCE] = delegate.attachedFields.getOrDefault(Constants.CLAIM_AUD, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_IAT)) {
            map[OAuth2IntrospectionClaimNames.ISSUED_AT] = delegate.attachedFields.getOrDefault(Constants.CLAIM_IAT, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_ISS)) {
            map[OAuth2IntrospectionClaimNames.ISSUER] = delegate.attachedFields.getOrDefault(Constants.CLAIM_ISS, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_NBF)) {
            map[OAuth2IntrospectionClaimNames.NOT_BEFORE] = delegate.attachedFields.getOrDefault(Constants.CLAIM_NBF, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_SUB)) {
            map[OAuth2IntrospectionClaimNames.SUBJECT] = delegate.attachedFields.getOrDefault(Constants.CLAIM_SUB, "")
        }

        delegate.attachedFields.forEach { (t, u) ->
            when (t) {
                Constants.CLAIM_EXP,
                Constants.CLAIM_AUD,
                Constants.CLAIM_IAT,
                Constants.CLAIM_ISS,
                Constants.CLAIM_NBF,
                Constants.CLAIM_SUB,
                Constants.CLAIM_USER_NAME,
                Constants.CLAIM_USER_ID -> {
                }
                else -> map[t] = u
            }
        }

        map
    }

    override fun getAttributes(): MutableMap<String, Any> = mergedAttributes

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return delegate.authorities
    }

    override fun getClaims(): MutableMap<String, Any> = attributes
}