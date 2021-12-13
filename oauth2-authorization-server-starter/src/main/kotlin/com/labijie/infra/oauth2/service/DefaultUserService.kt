package com.labijie.infra.oauth2.service

import com.labijie.infra.oauth2.IIdentityService
import com.labijie.infra.utils.ifNullOrBlank
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class DefaultUserService(private val identityService: IIdentityService) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        return identityService.getUserByName(username)?: throw UsernameNotFoundException("User with name '${username.ifNullOrBlank { "<empty>" }}' was not found")
    }
}