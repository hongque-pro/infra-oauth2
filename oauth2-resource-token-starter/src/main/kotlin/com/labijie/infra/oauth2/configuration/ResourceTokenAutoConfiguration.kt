package com.labijie.infra.oauth2.configuration

import com.labijie.caching.ICacheManager
import com.labijie.infra.oauth2.CachedRemoteTokenService
import com.labijie.infra.oauth2.DefaultTokenCache
import com.labijie.infra.oauth2.ITokenCache
import com.labijie.infra.oauth2.NoopTokenCache
import com.labijie.infra.utils.logger
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Conditional
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-10
 */
@Configuration
@AutoConfigureBefore(ResourceServerTokenServicesConfiguration::class)
@EnableConfigurationProperties(ResourceTokenProperties::class)
@Conditional(TokenInfoCondition::class)
@ConditionalOnProperty("security.oauth2.resource.token-cache-enabled", matchIfMissing = true)
class ResourceTokenAutoConfiguration {

    @Configuration
    @ConditionalOnClass(name = ["com.labijie.caching.ICacheManager"])
    protected class DefaultTokenCacheConfiguration {

        @Bean
        @ConditionalOnBean(ICacheManager::class)
        @ConditionalOnMissingBean(ITokenCache::class)
        fun defaultTokenCache(cacheManager: ICacheManager): ITokenCache {
            return DefaultTokenCache(cacheManager)
        }
    }

    @Configuration
    @AutoConfigureAfter(DefaultTokenCacheConfiguration::class)
    protected class NoopTokenCacheConfiguration {

        @Bean
        @ConditionalOnMissingBean(ITokenCache::class)
        fun noopTokenCache(): ITokenCache {
            logger.warn("No token cache used for remote token, because ICacheManager bean was not found. ")
            return NoopTokenCache()
        }
    }

    @Primary
    @Bean
    fun cachedRemoteTokenService(
        tokenCache: ITokenCache,
        resourceTokenProperties: ResourceTokenProperties,
        resourceServerProperties: ResourceServerProperties)
            : CachedRemoteTokenService {
        return CachedRemoteTokenService(
            tokenCache,
            resourceTokenProperties,
            resourceServerProperties
        )
    }
}