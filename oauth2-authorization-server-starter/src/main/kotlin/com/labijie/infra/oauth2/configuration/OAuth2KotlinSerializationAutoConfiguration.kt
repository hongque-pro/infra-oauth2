package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.serialization.kotlin.OAuth2KotlinCacheDataSerializerCustomizer
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/30
 *
 */

@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(name = ["kotlinx.serialization.KSerializer", "com.labijie.caching.redis.configuration.RedisCachingAutoConfiguration"])
@AutoConfigureBefore(name = ["com.labijie.caching.redis.configuration.RedisCachingAutoConfiguration"])
class OAuth2KotlinSerializationAutoConfiguration {

    companion object {
        private val logger by lazy {
            LoggerFactory.getLogger(OAuth2KotlinSerializationAutoConfiguration::class.java)
        }
    }

    @Bean
    @ConditionalOnMissingBean
    fun oauth2KotlinCacheDataSerializerCustomizer(): OAuth2KotlinCacheDataSerializerCustomizer {

        logger.info("OAuth2 kotlin serialization customizer loaded.")
        return OAuth2KotlinCacheDataSerializerCustomizer()
    }
}