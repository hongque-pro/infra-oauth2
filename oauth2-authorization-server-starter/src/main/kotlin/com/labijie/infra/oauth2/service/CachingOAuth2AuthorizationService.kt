package com.labijie.infra.oauth2.service

import com.labijie.caching.ICacheManager
import com.labijie.caching.get
import com.labijie.infra.oauth2.AuthorizationPlainObject
import com.labijie.infra.oauth2.AuthorizationPlainObject.Companion.expiresDurationMills
import com.labijie.infra.oauth2.AuthorizationPlainObject.Companion.tokenId
import com.labijie.infra.oauth2.OAuth2AuthorizationConverter
import com.labijie.infra.oauth2.OAuth2ServerUtils.md5Hex
import com.labijie.infra.oauth2.OAuth2ServerUtils.tokenId
import com.labijie.infra.oauth2.TokenPlainObject
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import java.time.Duration

class CachingOAuth2AuthorizationService(
    private val cache: ICacheManager) : OAuth2AuthorizationService {

    companion object{
        private fun getCacheKey(key: String) = "o2_tk_${key}"
        private fun getSateCacheKey(key: String) = "o2_tks_${key}"
        private fun getRefreshTokenCacheKey(key: String) = "o2_tkr_${key}"
    }

    override fun save(authorization: OAuth2Authorization) {
        val plainObject = OAuth2AuthorizationConverter.Instance.convertToPlain(authorization)
        val mills = plainObject.expiresDurationMills()
        if(mills != null && mills < 0){
            this.remove(authorization)
        }
        val expired = mills ?: Duration.ofDays(365).toMillis()
        val tokenId = plainObject.tokenId()
        val cacheKey = getCacheKey(tokenId)
        cache.set(cacheKey, plainObject, expired)
        val r = plainObject.refreshToken
        if(r != null){
            //连接一个缓存键
            val rk = r.getCacheKey()
            val exp = r.expiresDurationMills()
            if(exp == null || exp >= 0) {
                cache.set(rk, tokenId, exp)
            }
        }
        if(!plainObject.state.isNullOrBlank()){
            val key = getSateCacheKey(plainObject.state!!)
            cache.set(key, tokenId)
        }
    }

    private fun TokenPlainObject.getCacheKey(): String {
        val id = this.tokenId()
       return getRefreshTokenCacheKey(id)
    }

    override fun remove(authorization: OAuth2Authorization) {
        val tid = authorization.tokenId()
        val auth = cache.get(tid, AuthorizationPlainObject::class)
        if(auth != null){
            cache.remove(tid)
            //如果有 refresh token, 同时删除一下
            if(auth.refreshToken != null){
                val k = auth.refreshToken!!.getCacheKey()
                cache.remove(k)
            }
        }
    }

    override fun findById(id: String): OAuth2Authorization {
        throw UnsupportedOperationException("CachingOAuth2AuthorizationService findById is not supported")
    }

    override fun findByToken(token: String?, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        val tokenValue = if(token.isNullOrBlank()) throw IllegalArgumentException("token cannot be empty (findByToken)") else token

        val obj = if (tokenType == null || OAuth2ParameterNames.CODE == tokenType.value || OAuth2TokenType.ACCESS_TOKEN == tokenType) {
            val key = getCacheKey(tokenValue.md5Hex())
            cache.get(key, AuthorizationPlainObject::class)
        } else if (OAuth2ParameterNames.STATE == tokenType.value) {
            val key = getSateCacheKey(token)
            val tokenId = cache.get(key, String::class)
            if(!tokenId.isNullOrBlank()){
                val tk = getCacheKey(tokenId)
                cache.get(tk, AuthorizationPlainObject::class)
            }else{
                null
            }
        }else if (OAuth2TokenType.REFRESH_TOKEN == tokenType) {
            val key = getRefreshTokenCacheKey(tokenValue.md5Hex())
            val tokenId = cache.get(key, String::class)
            if(!tokenId.isNullOrBlank()){
                val tk = getCacheKey(tokenId)
                cache.get(tk, AuthorizationPlainObject::class)
            }else{
                null
            }
        }else{
            null
        }

        return if(obj != null) OAuth2AuthorizationConverter.Instance.convertFromPlain(obj) else null
    }

}