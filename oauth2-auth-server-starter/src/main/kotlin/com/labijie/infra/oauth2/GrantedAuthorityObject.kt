package com.labijie.infra.oauth2

import org.springframework.security.core.GrantedAuthority
import java.io.Serializable

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-12
 */
class GrantedAuthorityObject(@JvmField private var role: String = "") : GrantedAuthority, Serializable {

    companion object {
        @JvmStatic
        private val serialVersionUID:Long = 7804082565629023974L
    }

    override fun getAuthority() = role

    fun setAuthority(authority: String) {
        role = authority
    }
}