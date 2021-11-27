package com.labijie.infra.oauth2.serialization.kryo

import com.labijie.caching.redis.configuration.IKryoCacheDataSerializerCustomizer
import com.labijie.caching.redis.serialization.KryoOptions
import com.labijie.infra.oauth2.AccessTokenPlainObject
import com.labijie.infra.oauth2.AuthorizationPlainObject
import com.labijie.infra.oauth2.TokenPlainObject
import org.springframework.core.Ordered

class OAuth2KryoCacheDataSerializerCustomizer : IKryoCacheDataSerializerCustomizer {
    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE
    override fun customize(options: KryoOptions) {
        options.registerClass(501, AuthorizationPlainObject::class)
        options.registerClass(502, TokenPlainObject::class)
        options.registerClass(503, AccessTokenPlainObject::class)
    }
}