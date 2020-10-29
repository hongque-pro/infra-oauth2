package com.labijie.infra.oauth2.configuration

import com.labijie.infra.oauth2.AuthorizationServerSwitch
import com.labijie.infra.oauth2.ResourceServerSwitch
import com.labijie.infra.oauth2.annotation.*
import com.labijie.infra.oauth2.configuration.token.InMemoryTokenStoreConfiguration
import com.labijie.infra.oauth2.configuration.token.JwtTokenStoreConfiguration
import com.labijie.infra.oauth2.configuration.token.RedisTokenStoreConfiguration
import org.springframework.context.annotation.ImportSelector
import org.springframework.core.type.AnnotationMetadata

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class TokenStoreImportSelector : ImportSelector {
    override fun selectImports(importingClassMetadata: AnnotationMetadata): Array<String> {
        val attributes = importingClassMetadata.getAnnotationAttributes(EnableOAuth2Server::class.java.name)
        val beans = mutableSetOf<String>()

        val tokenStoreType = attributes!![EnableOAuth2Server::tokeStore.name] as TokenStoreType

        when (tokenStoreType) {
            TokenStoreType.Jwt -> beans.add(JwtTokenStoreConfiguration::class.java.name)
            TokenStoreType.Redis -> beans.add(RedisTokenStoreConfiguration::class.java.name)
            TokenStoreType.InMemory -> beans.add(InMemoryTokenStoreConfiguration::class.java.name)
            else -> {
            }
        }

        @Suppress("UNCHECKED_CAST")
        val serverTypes = attributes[EnableOAuth2Server::include.name] as Array<OAuth2ServerType>

        if (serverTypes.contains(OAuth2ServerType.Authorization)) {
            beans.add(AuthorizationServerSwitch::class.java.name)
            beans.add(WebSecurityAutoConfiguration::class.java.name)
        }

        if (serverTypes.contains(OAuth2ServerType.Resource)) {
            beans.add(ResourceServerSwitch::class.java.name)
        }

        return beans.toTypedArray()
    }
}