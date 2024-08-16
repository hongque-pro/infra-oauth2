/**
 * @author Anders Xiao
 * @date 2024-08-17
 */
package com.labijie.infra.oauth2.customizer

import com.labijie.infra.oauth2.ITwoFactorUserDetails
import org.springframework.security.authentication.AbstractAuthenticationToken


class TwoFactorGrantedAuthentication(private val principal: ITwoFactorUserDetails) : AbstractAuthenticationToken(null) {

    init {
        super.setAuthenticated(true)
    }

    override fun getCredentials(): Any? {
        return null
    }

    override fun getPrincipal(): Any {
        return principal
    }
}