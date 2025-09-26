package com.labijie.infra.oauth2.client.provider.apple

import com.labijie.caching.ICacheManager
import com.labijie.caching.get
import com.labijie.caching.set

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/19
 *
 */
class CachingAppleIdOneTimeStore(private val cacheManager: ICacheManager) : IAppleIdOneTimeStore {

    val cacheRegion: String? = null

    private fun String.getCacheKey(): String {
        return "apple_id:${this}"
    }

    override fun save(key: String, info: AppleOneTimeIdentifier) {
        cacheManager.set<AppleOneTimeIdentifier>(key.getCacheKey(), info, region = cacheRegion)
    }

    override fun get(key: String): AppleOneTimeIdentifier? {
        return cacheManager.get<AppleOneTimeIdentifier>(key.getCacheKey())
    }

    override fun remove(key: String) {
        cacheManager.remove(key, cacheRegion)
    }
}