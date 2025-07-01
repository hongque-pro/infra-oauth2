package com.labijie.infra.oauth2.serialization.kotlin

import com.labijie.caching.redis.customization.IKotlinCacheDataSerializerCustomizer
import com.labijie.infra.oauth2.AuthorizationPlainObject
import kotlinx.serialization.KSerializer
import kotlin.reflect.KType
import kotlin.reflect.typeOf

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/30
 *
 */
@Suppress("UNCHECKED_CAST")
class OAuth2KotlinCacheDataSerializerCustomizer : IKotlinCacheDataSerializerCustomizer {
    override fun customSerializers(): Map<KType, KSerializer<Any?>> {
        return mapOf(
            (typeOf<AuthorizationPlainObject>() to AuthorizationPlainObjectKSerializer as KSerializer<Any?>)
        )
    }
}