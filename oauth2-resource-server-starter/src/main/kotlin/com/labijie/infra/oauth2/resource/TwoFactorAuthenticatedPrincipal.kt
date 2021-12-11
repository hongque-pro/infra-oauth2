package com.labijie.infra.oauth2.resource

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.TwoFactorPrincipal
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import java.io.Serializable

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 19:19
 * @Description:
 */

class TwoFactorAuthenticatedPrincipal(private val delegate: TwoFactorPrincipal) : OAuth2AuthenticatedPrincipal,
    OAuth2TokenIntrospectionClaimAccessor, Serializable {
    override fun getName(): String = delegate.userName

    fun getTwoFactorPrincipal(): TwoFactorPrincipal {
        return this.delegate
    }

    private val mergedAttributes by lazy {
        val map = mutableMapOf<String, Any>()
        map[OAuth2TokenIntrospectionClaimNames.ACTIVE] = true
        map[Constants.CLAIM_USER_ID] = delegate.userId
        map[OAuth2TokenIntrospectionClaimNames.USERNAME] = delegate.userName

        if (delegate.attachedFields.containsKey(Constants.CLAIM_EXP)) {
            map[OAuth2TokenIntrospectionClaimNames.EXP] = delegate.attachedFields.getOrDefault(Constants.CLAIM_EXP, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_AUD)) {
            map[OAuth2TokenIntrospectionClaimNames.AUD] = delegate.attachedFields.getOrDefault(Constants.CLAIM_AUD, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_IAT)) {
            map[OAuth2TokenIntrospectionClaimNames.IAT] = delegate.attachedFields.getOrDefault(Constants.CLAIM_IAT, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_ISS)) {
            map[OAuth2TokenIntrospectionClaimNames.ISS] = delegate.attachedFields.getOrDefault(Constants.CLAIM_ISS, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_NBF)) {
            map[OAuth2TokenIntrospectionClaimNames.NBF] = delegate.attachedFields.getOrDefault(Constants.CLAIM_NBF, "")
        }

        if (delegate.attachedFields.containsKey(Constants.CLAIM_SUB)) {
            map[OAuth2TokenIntrospectionClaimNames.SUB] = delegate.attachedFields.getOrDefault(Constants.CLAIM_SUB, "")
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