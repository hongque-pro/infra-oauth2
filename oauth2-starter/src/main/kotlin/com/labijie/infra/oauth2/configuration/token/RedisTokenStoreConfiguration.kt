package com.labijie.infra.oauth2.configuration.token

import com.labijie.infra.oauth2.token.TwoFactorAuthenticationConverter
import org.apache.tomcat.util.http.parser.Authorization
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.redis.*

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class RedisTokenStoreConfiguration {

    @Bean
    fun redisTokenStore(redisConnectionFactory: RedisConnectionFactory):RedisTokenStore{
        return RedisTokenStore(redisConnectionFactory)
    }
}