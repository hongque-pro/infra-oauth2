package com.labijie.dummy.auth

import com.labijie.infra.oauth2.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class DummyIdentityService(private val passwordEncoder: PasswordEncoder): IIdentityService {

    override fun getUserByName(userName: String): ITwoFactorUserDetails {
        val obj = object: ITwoFactorUserDetails {

            private val passwordHash = passwordEncoder.encode(DummyConstants.userPassword)

            override fun getUserId(): String {
                return "123456789"
            }

            override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
                return mutableListOf(SimpleGrantedAuthority("ROLE_aa"))
            }

            override fun isEnabled(): Boolean = true

            override fun getUsername(): String = userName

            override fun isCredentialsNonExpired(): Boolean = true

            override fun getPassword(): String = passwordHash

            override fun isAccountNonExpired(): Boolean = true

            override fun isAccountNonLocked(): Boolean = true

            override fun isTwoFactorEnabled(): Boolean = true

            override fun getTokenAttributes(): Map<String, String> {
                return mapOf("aaa" to "test")
            }
        }
        return SimpleTwoFactorUserDetails.fromUserDetails(obj)
    }

}