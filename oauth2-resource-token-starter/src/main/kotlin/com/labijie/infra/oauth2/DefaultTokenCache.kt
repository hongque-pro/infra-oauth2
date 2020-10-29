package com.labijie.infra.oauth2

import com.fasterxml.jackson.core.type.TypeReference
import com.labijie.caching.ICacheManager
import com.labijie.infra.utils.logger
import com.labijie.infra.utils.throwIfNecessary

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
class DefaultTokenCache(private val cacheManager: ICacheManager):
    ITokenCache {
    override fun get(tokenId: String, region: String): Map<String, String>? {
        return try{
            val type = object: TypeReference<Map<String, String>>(){}
            @Suppress("UNCHECKED_CAST")
            this. cacheManager.get(tokenId, type.type, region) as? Map<String, String>
        }catch (e:Throwable){
            logger.warn("Get token from cache fault.", e)
            e.throwIfNecessary()
            null
        }
    }

    override fun set(tokenId: String, tokenData: Map<String, String>, region: String, timeoutMills: Long) {
        this.cacheManager.set(tokenId, tokenData, timeoutMills, region = region)
    }
}