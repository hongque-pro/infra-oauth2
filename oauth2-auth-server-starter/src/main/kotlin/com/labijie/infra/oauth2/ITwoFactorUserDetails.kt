package com.labijie.infra.oauth2

import org.springframework.security.core.userdetails.UserDetails

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-25
 */
interface ITwoFactorUserDetails : UserDetails {
    fun getUserId(): String
    fun isTwoFactorEnabled(): Boolean

    fun getAttachedTokenFields() : Map<String, String> {
        return mapOf()
    }
}