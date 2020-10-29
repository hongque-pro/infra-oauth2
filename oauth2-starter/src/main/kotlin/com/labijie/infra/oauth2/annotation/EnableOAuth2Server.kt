package com.labijie.infra.oauth2.annotation

import com.labijie.infra.oauth2.configuration.OAuth2ServerConfig
import com.labijie.infra.oauth2.configuration.TokenStoreImportSelector
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Import

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
@Import(TokenStoreImportSelector::class)
@EnableConfigurationProperties(OAuth2ServerConfig::class)
annotation class EnableOAuth2Server(vararg val include: OAuth2ServerType, val tokeStore: TokenStoreType = TokenStoreType.Jwt)