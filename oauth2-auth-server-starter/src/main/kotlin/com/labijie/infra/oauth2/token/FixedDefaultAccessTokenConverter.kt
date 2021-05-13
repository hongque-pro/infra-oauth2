package com.labijie.infra.oauth2.token

import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter

class FixedDefaultAccessTokenConverter : DefaultAccessTokenConverter() {

    override fun extractAccessToken(value: String?, map: MutableMap<String, *>?): OAuth2AccessToken? {
        if (map != null && map.containsKey(EXP)) {
            if (map[EXP] !is Long) {
                val v = map.getOrDefault(EXP, null)?.toString()?.toLong()
                if (v != null) {
                    val m = map as MutableMap<String, Any>
                    m[EXP] = v
                }
            }
        }
        return super.extractAccessToken(value, map)
    }
}