package com.labijie.infra.oauth2.dummy

import com.labijie.infra.oauth2.IIdentityService
import com.labijie.infra.oauth2.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
@Service
class DummyIdentityService: IIdentityService {

    private val passwordEncoder = BCryptPasswordEncoder()

    override fun getUserByName(userName: String): ITwoFactorUserDetails {
        val obj = object: ITwoFactorUserDetails {

            override fun getUserId(): String {
                return this.username.hashCode().toString()
            }

            override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
                return mutableListOf(GrantedAuthorityObject("aa"))
            }

            override fun isEnabled(): Boolean = true

            override fun getUsername(): String = "dummy-user"

            override fun isCredentialsNonExpired(): Boolean = true

            override fun getPassword(): String = passwordEncoder.encode("123")

            override fun isAccountNonExpired(): Boolean = true

            override fun isAccountNonLocked(): Boolean = true

            override fun isTwoFactorEnabled(): Boolean = true

            override fun getTokenAttributes(): Map<String, String> {
                return mapOf("test-attached-field" to "tf-value")
            }
        }
        return SimpleTwoFactorUserDetails.fromUserDetails(obj)
    }

    override fun authenticationChecks(authenticationCheckingContext: AuthenticationCheckingContext): SignInResult {
        return SignInResult(type = SignInResultType.TwoFactorRequired, user = authenticationCheckingContext.userDetails)
    }
}