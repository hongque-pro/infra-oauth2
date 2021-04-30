package com.labijie.infra.oauth2

import com.fasterxml.jackson.annotation.JsonIgnore
import org.springframework.security.core.GrantedAuthority

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-15
 */
data class TwoFactorPrincipal(
        val userId: String,
        val userName: String,
        val isTwoFactorGranted: Boolean,
        val authorities: MutableCollection<GrantedAuthority>,
        val attachedFields: Map<String, String>) {

    @get:JsonIgnore
    val roleNames: List<String> by lazy {
        this.authorities.filter { it.authority.startsWith(Constants.ROLE_AUTHORITY_PREFIX) }.map { it.authority }
    }

}