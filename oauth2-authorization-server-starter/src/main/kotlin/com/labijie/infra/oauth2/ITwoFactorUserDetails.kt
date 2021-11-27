package com.labijie.infra.oauth2

import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-25
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS, include = JsonTypeInfo.As.EXISTING_PROPERTY)
interface ITwoFactorUserDetails : UserDetails {
    fun getUserId(): String
    fun isTwoFactorEnabled(): Boolean

    fun getTokenAttributes() : Map<String, String> {
        return mapOf()
    }

    companion object {
       fun fromPlainObject(userObject: UserPlainObject): ITwoFactorUserDetails {
           val authorities = userObject.authorities.map { SimpleGrantedAuthority(it) }
           return SimpleTwoFactorUserDetails(
               userObject.userid,
               userObject.username,
               userObject.credentialsNonExpired,
               userObject.enabled,
               userObject.password,
               userObject.accountNonExpired,
               userObject.accountNonLocked,
               userObject.twoFactorEnabled,
               ArrayList(authorities),
               userObject.attachedFields
           )
       }
    }
}

fun ITwoFactorUserDetails.toPlainObject(): UserPlainObject {
    return UserPlainObject(
        this.getUserId(),
        this.username,
        this.isCredentialsNonExpired,
        this.isEnabled,
        this.password,
        this.isAccountNonExpired,
        this.isAccountNonLocked,
        this.isTwoFactorEnabled(),
        ArrayList(this.authorities.map { it.authority }),
        HashMap(this.getTokenAttributes())
    )
}

fun ITwoFactorUserDetails.withoutPassword(): ITwoFactorUserDetails {
    return SimpleTwoFactorUserDetails.fromUserDetails(this, true)
}