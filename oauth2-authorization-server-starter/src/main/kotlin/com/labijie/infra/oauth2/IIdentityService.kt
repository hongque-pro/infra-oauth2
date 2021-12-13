package com.labijie.infra.oauth2

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
interface IIdentityService {
    fun getUserByName(userName: String): ITwoFactorUserDetails?
}