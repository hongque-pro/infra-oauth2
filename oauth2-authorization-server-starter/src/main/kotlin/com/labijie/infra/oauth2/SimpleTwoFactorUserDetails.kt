package com.labijie.infra.oauth2

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.io.Serializable

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class SimpleTwoFactorUserDetails(
        @JvmField private val userid:String = "",
        @JvmField private val username:String = "",
        @JvmField private val credentialsNonExpired:Boolean = false,
        @JvmField private val enabled:Boolean = false,
        @JvmField private val password:String = "",
        @JvmField private val accountNonExpired:Boolean = false,
        @JvmField private val accountNonLocked:Boolean = false,
        @JvmField private val twoFactorEnabled: Boolean = false,
        @JvmField private val authorities:ArrayList<SimpleGrantedAuthority> = arrayListOf(),
        @JvmField  private val attachedFields:Map<String, String> = mapOf()) : ITwoFactorUserDetails, Serializable {

    override fun getUserId(): String {
        return this.userid
    }

    companion object {

        @JvmStatic
        private val serialVersionUID:Long = 7804082565629023975L

        fun fromUserDetails(userDetails: ITwoFactorUserDetails, removePassword: Boolean = false): SimpleTwoFactorUserDetails {
            return SimpleTwoFactorUserDetails(
                    userDetails.getUserId(),
                    userDetails.username,
                    userDetails.isCredentialsNonExpired,
                    userDetails.isEnabled,
                    if(removePassword) "" else userDetails.password,
                    userDetails.isAccountNonExpired,
                    userDetails.isAccountNonLocked,
                    userDetails.isTwoFactorEnabled(),
                    ArrayList(userDetails.authorities.map { g->SimpleGrantedAuthority(g.authority) }),
                    userDetails.getTokenAttributes())
        }
    }

    override fun isTwoFactorEnabled(): Boolean {
        return twoFactorEnabled
    }

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = authorities

    override fun isEnabled(): Boolean = enabled

    override fun getUsername() = username

    override fun isCredentialsNonExpired() = credentialsNonExpired

    override fun getPassword() = password

    override fun isAccountNonExpired() = accountNonExpired

    override fun isAccountNonLocked() = accountNonLocked

    override fun getTokenAttributes(): Map<String, String> {
        return attachedFields
    }
}