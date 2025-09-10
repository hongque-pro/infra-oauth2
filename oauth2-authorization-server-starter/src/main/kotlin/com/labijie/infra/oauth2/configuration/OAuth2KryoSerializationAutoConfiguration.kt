package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.serialization.kryo.OAuth2KryoCacheDataSerializerCustomizer
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/10
 *
 */

@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(name = ["com.labijie.caching.redis.configuration.RedisCachingAutoConfiguration", "com.esotericsoftware.kryo.Kryo"])
@AutoConfigureBefore(name = ["com.labijie.caching.redis.configuration.RedisCachingAutoConfiguration"])
class OAuth2KryoSerializationAutoConfiguration {

    companion object {
        private val logger by lazy {

            LoggerFactory.getLogger(OAuth2KryoSerializationAutoConfiguration::class.java)
        }
    }

    @Bean
    fun oauth2KryoCacheDataSerializerCustomizer(): OAuth2KryoCacheDataSerializerCustomizer {
        logger.info("OAuth2 kryo serialization customizer loaded.")
        return OAuth2KryoCacheDataSerializerCustomizer()
    }
}