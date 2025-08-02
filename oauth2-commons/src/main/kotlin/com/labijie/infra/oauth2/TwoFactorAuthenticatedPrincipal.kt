package com.labijie.infra.oauth2

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
        map[OAuth2Constants.CLAIM_USER_ID] = delegate.userId
        map[OAuth2TokenIntrospectionClaimNames.USERNAME] = delegate.userName

        if (delegate.attachedFields.containsKey(OAuth2Constants.CLAIM_EXP)) {
            map[OAuth2TokenIntrospectionClaimNames.EXP] = delegate.attachedFields.getOrDefault(OAuth2Constants.CLAIM_EXP, "")
        }

        if (delegate.attachedFields.containsKey(OAuth2Constants.CLAIM_AUD)) {
            map[OAuth2TokenIntrospectionClaimNames.AUD] = delegate.attachedFields.getOrDefault(OAuth2Constants.CLAIM_AUD, "")
        }

        if (delegate.attachedFields.containsKey(OAuth2Constants.CLAIM_IAT)) {
            map[OAuth2TokenIntrospectionClaimNames.IAT] = delegate.attachedFields.getOrDefault(OAuth2Constants.CLAIM_IAT, "")
        }

        if (delegate.attachedFields.containsKey(OAuth2Constants.CLAIM_ISS)) {
            map[OAuth2TokenIntrospectionClaimNames.ISS] = delegate.attachedFields.getOrDefault(OAuth2Constants.CLAIM_ISS, "")
        }

        if (delegate.attachedFields.containsKey(OAuth2Constants.CLAIM_NBF)) {
            map[OAuth2TokenIntrospectionClaimNames.NBF] = delegate.attachedFields.getOrDefault(OAuth2Constants.CLAIM_NBF, "")
        }

        if (delegate.attachedFields.containsKey(OAuth2Constants.CLAIM_SUB)) {
            map[OAuth2TokenIntrospectionClaimNames.SUB] = delegate.attachedFields.getOrDefault(OAuth2Constants.CLAIM_SUB, "")
        }

        delegate.attachedFields.forEach { (t, u) ->
            when (t) {
                OAuth2Constants.CLAIM_EXP,
                OAuth2Constants.CLAIM_AUD,
                OAuth2Constants.CLAIM_IAT,
                OAuth2Constants.CLAIM_ISS,
                OAuth2Constants.CLAIM_NBF,
                OAuth2Constants.CLAIM_SUB,
                OAuth2Constants.CLAIM_USER_NAME,
                OAuth2Constants.CLAIM_USER_ID -> {
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