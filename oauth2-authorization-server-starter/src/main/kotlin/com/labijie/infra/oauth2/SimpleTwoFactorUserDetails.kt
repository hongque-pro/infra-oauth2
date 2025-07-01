package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.MetadataTypedValue.Companion.getValue
import com.labijie.infra.oauth2.MetadataTypedValue.Companion.toMetadataValue
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.io.Serializable
import java.net.URLDecoder
import java.net.URLEncoder
import kotlin.collections.ArrayList

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class SimpleTwoFactorUserDetails(
        private val userid:String = "",
        private val username:String = "",
        private val credentialsNonExpired:Boolean = false,
        private val enabled:Boolean = false,
        private val password:String = "",
        private val accountNonExpired:Boolean = false,
        private val accountNonLocked:Boolean = false,
        private val twoFactorEnabled: Boolean = false,
        private val authorities:ArrayList<SimpleGrantedAuthority> = arrayListOf(),
        private val attachedFields:Map<String, String> = mapOf()) : ITwoFactorUserDetails, Serializable {


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