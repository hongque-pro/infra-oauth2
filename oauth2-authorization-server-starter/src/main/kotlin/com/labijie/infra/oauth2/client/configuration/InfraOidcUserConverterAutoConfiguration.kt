package com.labijie.infra.oauth2.client.configuration

import com.labijie.infra.oauth2.client.converter.AppleOidcUserConverter
import com.labijie.infra.oauth2.client.converter.DiscordOidcUserConverter
import com.labijie.infra.oauth2.client.converter.GithubOidcUserConverter
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE - 1)
class InfraOidcUserConverterAutoConfiguration {

    @Bean
    fun appleOidcUserConverter() : AppleOidcUserConverter {
        return AppleOidcUserConverter
    }

    @Bean
    fun discordOidcUserConverter() : DiscordOidcUserConverter {
        return DiscordOidcUserConverter
    }

    @Bean
    fun githubOidcUserConverter() : GithubOidcUserConverter {
        return GithubOidcUserConverter
    }
}