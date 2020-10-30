package com.labijie.infra.oauth2.configuration.token

import com.labijie.infra.oauth2.AuthorizationServerSwitch
import com.labijie.infra.oauth2.ResourceServerSwitch
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.configuration.JwtKeyType
import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.oauth2.token.TwoFactorAuthenticationConverter
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import java.security.KeyPair

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
class JwtTokenStoreConfiguration {

    companion object {
        private val logger = LoggerFactory.getLogger(JwtTokenStoreConfiguration::class.java)!!
    }

    private var isAuthenticationServer = false
    private var isResourceServer = false

    @Autowired
    private fun init(@Autowired(required = false) resourceServerConfiguration: AuthorizationServerSwitch?,
                @Autowired(required = false) serverConfiguration: ResourceServerSwitch?){
        this.isAuthenticationServer = (serverConfiguration != null)
        this.isResourceServer = (resourceServerConfiguration != null)
    }

    @Bean
    fun jwtAccessTokenConverter(oAuth2Config: OAuth2ServerProperties): JwtAccessTokenConverter {

        val converter = JwtAccessTokenConverter()
        converter.accessTokenConverter = DefaultAccessTokenConverter().apply {
            this.setUserTokenConverter(TwoFactorAuthenticationConverter)
        }
        when (oAuth2Config.token.jwt.keyType) {
            JwtKeyType.RSA -> {
                if (isAuthenticationServer) {
                    configAuthenticationRSA(converter, oAuth2Config)
                }
            }
            JwtKeyType.Simple -> {
                if (oAuth2Config.token.jwt.simpleKey.isBlank()) {
                    throw IllegalArgumentException("miss configuration property: infra.oauth2.token.jwt.simpleKey")
                }
                converter.setSigningKey(oAuth2Config.token.jwt.simpleKey)
            }
        }
        logger.info("Jwt token is used, key type: ${oAuth2Config.token.jwt.keyType}")
        return converter
    }

    private fun configAuthenticationRSA(converter: JwtAccessTokenConverter, oAuth2Config: OAuth2ServerProperties) {
        if (oAuth2Config.token.jwt.rsa.privateKey.isBlank()) {
            throw IllegalArgumentException("miss configuration property: infra.oauth2.token.jwt.rsa.privateKey")
        }
        if (oAuth2Config.token.jwt.rsa.privateKey.isBlank()) {
            throw IllegalArgumentException("miss configuration property: infra.oauth2.token.jwt.rsa.privateKey")
        }
        val privateKey = RsaUtils.getPrivateKey(oAuth2Config.token.jwt.rsa.privateKey)
        val publicKey = RsaUtils.getPublicKey(oAuth2Config.token.jwt.rsa.publicKey)
        converter.setKeyPair(KeyPair(publicKey, privateKey))
    }

    @Bean
    fun jwtTokenStore(converter: JwtAccessTokenConverter): TokenStore {
        return JwtTokenStore(converter)
    }
}