package com.labijie.infra.oauth2.service

import com.labijie.caching.ICacheItem
import com.labijie.caching.ICacheManager
import com.labijie.caching.get
import com.labijie.infra.oauth2.AuthorizationPlainObject
import com.labijie.infra.oauth2.AuthorizationPlainObject.Companion.expiresDurationMills
import com.labijie.infra.oauth2.AuthorizationPlainObject.Companion.tokenId
import com.labijie.infra.oauth2.OAuth2AuthorizationConverter
import com.labijie.infra.oauth2.OAuth2ServerUtils.tokenId
import com.labijie.infra.oauth2.TokenPlainObject
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import java.time.Duration

class CachingOAuth2AuthorizationService(
    private val cache: ICacheManager,
    private val cachingRegion: String? = null
) : OAuth2AuthorizationService {


    companion object {
        private fun getAccessTokenCacheKey(tokenId: String) = "o2_tk_${tokenId}"
        private fun getSateCacheKey(key: String) = "o2_tks_${key}"
        private fun getRefreshTokenCacheKey(tokenId: String) = "o2_tkr_${tokenId}"
    }

    override fun save(authorization: OAuth2Authorization) {
        val plainObject = OAuth2AuthorizationConverter.Instance.convertToPlain(authorization)
        val mills = plainObject.expiresDurationMills()
        if (mills != null && mills < 0) {
            this.remove(authorization)
        }
        val tokenExp = mills ?: Duration.ofDays(365).toMillis()
        val tokenId = plainObject.tokenId()
        val cacheKey = getAccessTokenCacheKey(tokenId)

        val refreshTokenExp = (plainObject.refreshToken?.expiresDurationMills() ?: 0).coerceAtLeast(tokenExp)

        val map = mutableMapOf<String, ICacheItem>()
        //1. access token
        map.put(cacheKey, ICacheItem.of(plainObject))

        val r = plainObject.refreshToken
        if (r != null) {
            //连接一个缓存键
            val rk = r.getRefreshTokenCacheKey()
            //2. refresh token
            map.put(rk, ICacheItem.of(tokenId))
        }
        val state = plainObject.state
        if (!state.isNullOrBlank()) {
            val key = getSateCacheKey(state)
            //2. state
            map.put(key, ICacheItem.of(tokenId))
        }
        cache.setMulti(map, refreshTokenExp, region = cachingRegion)
    }

    private fun TokenPlainObject.getRefreshTokenCacheKey(): String {
        val id = this.tokenId()
        return getRefreshTokenCacheKey(id)
    }

    override fun remove(authorization: OAuth2Authorization) {
        val tid = authorization.tokenId()
        val auth = cache.get<AuthorizationPlainObject>(tid, region = cachingRegion)
        if (auth != null) {
            val keys = mutableSetOf<String>()
            keys.add((tid))
            //cache.remove(tid, region = this.cachingRegion)
            //如果有 refresh token, 同时删除一下
            if (auth.refreshToken != null) {
                val k = auth.refreshToken!!.getRefreshTokenCacheKey()
                //cache.remove(k, region = this.cachingRegion)
                keys.add((k))
            }
            if (!auth.state.isNullOrBlank()) {
                val key = getSateCacheKey(auth.state!!)
                //cache.remove(key, region = this.cachingRegion)
                keys.add((key))
            }
            cache.removeMulti(keys)
        }
    }

    override fun findById(id: String): OAuth2Authorization {
        throw UnsupportedOperationException("CachingOAuth2AuthorizationService findById is not supported")
    }

    override fun findByToken(token: String?, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        val tokenValue =
            if (token.isNullOrBlank()) throw IllegalArgumentException("token cannot be empty (findByToken)") else token

        val obj =
            if (tokenType == null || OAuth2ParameterNames.CODE == tokenType.value || OAuth2TokenType.ACCESS_TOKEN == tokenType) {
                val id = AuthorizationPlainObject.tokenValueToId(tokenValue)
                val key = getAccessTokenCacheKey(id)
                cache.get<AuthorizationPlainObject>(key, region = this.cachingRegion)
            } else if (OAuth2ParameterNames.STATE == tokenType.value) {
                val key = getSateCacheKey(token)
                val tokenId = cache.get<String>(key)
                if (!tokenId.isNullOrBlank()) {
                    val tk = getAccessTokenCacheKey(tokenId)
                    cache.get<AuthorizationPlainObject>(tk, region = this.cachingRegion)
                } else {
                    null
                }
            } else if (OAuth2TokenType.REFRESH_TOKEN == tokenType) {
                val id = AuthorizationPlainObject.tokenValueToId(tokenValue)
                val key = getRefreshTokenCacheKey(id)
                val tokenId = cache.get<String>(key, region = this.cachingRegion)
                if (!tokenId.isNullOrBlank()) {
                    val tk = getAccessTokenCacheKey(tokenId)
                    cache.get<AuthorizationPlainObject>(tk, region = this.cachingRegion)
                } else {
                    null
                }
            } else {
                null
            }

        return if (obj != null) OAuth2AuthorizationConverter.Instance.convertFromPlain(obj) else null
    }

}