package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.oauth2.configuration.TokenStoreType
import com.labijie.infra.oauth2.token.TwoFactorAuthenticationConverter
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.FactoryBean
import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.config.AutowireCapableBeanFactory
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore
import java.security.KeyPair

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 22:55
 * @Description:
 */
class TokenStoreFactoryBean(
        private val serverProperties: OAuth2ServerProperties) : FactoryBean<TokenStore>, ApplicationContextAware {
    companion object {
        @JvmStatic
        private val logger = LoggerFactory.getLogger(TokenStoreFactoryBean::class.java)

        fun jwtAccessTokenConverter(oAuth2Config: OAuth2ServerProperties): JwtAccessTokenConverter {
            val converter = JwtAccessTokenConverter()
            converter.accessTokenConverter = DefaultAccessTokenConverter().apply {
                this.setUserTokenConverter(TwoFactorAuthenticationConverter)
            }
            configAuthenticationRSA(converter, oAuth2Config)
            return converter
        }

        private fun configAuthenticationRSA(converter: JwtAccessTokenConverter, oAuth2Config: OAuth2ServerProperties) {
            val kp = if (oAuth2Config.token.jwt.rsa.privateKey.isBlank() || oAuth2Config.token.jwt.rsa.publicKey.isBlank()) {
                logger.warn("Jwt token store rsa key pair not found, default key will be used.")
                RsaUtils.defaultKeyPair
            }else{
                val privateKey = RsaUtils.getPrivateKey(oAuth2Config.token.jwt.rsa.privateKey)
                val publicKey = RsaUtils.getPublicKey(oAuth2Config.token.jwt.rsa.publicKey)
                KeyPair(publicKey, privateKey)
            }

            converter.setKeyPair(kp)
        }
    }

    private lateinit var context: ApplicationContext





    private fun createJwtTokenStore(): TokenStore {
        val converter = jwtAccessTokenConverter(this.serverProperties)
        return JwtTokenStore(converter)
    }


    override fun getObject(): TokenStore {
        return when(this.serverProperties.token.store){
            TokenStoreType.Redis-> {
                context.autowireCapableBeanFactory.autowire(RedisTokenStore::class.java, AutowireCapableBeanFactory.AUTOWIRE_CONSTRUCTOR, true) as TokenStore
            }
            TokenStoreType.Jwt->createJwtTokenStore()
            else->  InMemoryTokenStore().apply {
                this.flushInterval = (serverProperties.token.accessTokenExpiration.toMillis() / 3).coerceAtLeast(1000).toInt()
            }
        }
    }

    override fun getObjectType(): Class<*>? {
        return TokenStore::class.java
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        context = applicationContext
    }
}