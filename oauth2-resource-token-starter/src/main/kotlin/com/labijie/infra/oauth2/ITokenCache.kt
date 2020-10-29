package com.labijie.infra.oauth2

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
interface ITokenCache {
    fun get(tokenId: String, region: String): Map<String, String>?
    fun set(tokenId: String, tokenData: Map<String, String>, region: String, timeoutMills: Long)
}