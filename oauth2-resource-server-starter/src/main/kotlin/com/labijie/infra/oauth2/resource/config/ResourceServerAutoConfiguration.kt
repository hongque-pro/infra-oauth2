package com.labijie.infra.oauth2.resource.config

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.ITokenIntrospectionParser
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.resource.LocalOpaqueTokenIntrospector
import com.labijie.infra.oauth2.resource.expression.OAuth2TwoFactorSecurityExpressionHandler
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.TypeDescriptor
import org.springframework.core.convert.converter.Converter
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.converter.ClaimConversionService
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Duration
import java.util.*


@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableConfigurationProperties(ResourceServerProperties::class)
@ConditionalOnBean(OAuth2ResourceServerProperties::class)
class ResourceServerAutoConfiguration(
        private val oauth2ResProperties: OAuth2ResourceServerProperties,
        private val resourceConfigurers: ObjectProvider<IResourceAuthorizationConfigurer>,
        private val resourceServerProperties: ResourceServerProperties) : WebSecurityConfigurerAdapter(false) {


    companion object {
        private val OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Any::class.java)
        private val STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String::class.java)
        private val BOOL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean::class.java)


        private fun getConverter(targetDescriptor: TypeDescriptor): Converter<Any, *> {
            return Converter { source: Any -> ClaimConversionService.getSharedInstance().convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor) }
        }


//        fun genHS256Key(key: String): SecretKey {
//            val encodedKey: ByteArray = key.toByteArray(Charsets.UTF_8)
//            return SecretKeySpec(encodedKey, 0, encodedKey.size, JwsAlgorithms.HS256)
//        }
    }

    @Bean
    @ConditionalOnMissingBean(LocalOpaqueTokenIntrospector::class)
    @ConditionalOnBean(ITokenIntrospectionParser::class)
    fun localOpaqueTokenIntrospector(tokenIntrospectionParser: ITokenIntrospectionParser): LocalOpaqueTokenIntrospector {
        return LocalOpaqueTokenIntrospector(tokenIntrospectionParser)
    }

    fun applyJwtConfiguration(
            configurer: OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer): OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer {
        //参考：https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver-jwt-decoder-secret-key
        val decoder = if (resourceServerProperties.jwt.jwkPubKey.isNotBlank()) {
            val rsaPubKey = RsaUtils.getPublicKey(resourceServerProperties.jwt.jwkPubKey) as RSAPublicKey
            NimbusJwtDecoder.withPublicKey(rsaPubKey)
                    .build()
        } else if (!oauth2ResProperties.jwt.jwkSetUri.isNullOrBlank()) {
            NimbusJwtDecoder.withJwkSetUri(oauth2ResProperties.jwt.jwkSetUri)
                    .build()
        } else if (!oauth2ResProperties.jwt.publicKeyLocation.exists()) {
            val pubKey = RsaUtils.getPublicKey(oauth2ResProperties.jwt.readPublicKey())
            NimbusJwtDecoder.withPublicKey(pubKey)
                    .build()
        } else {
            NimbusJwtDecoder.withPublicKey(RsaUtils.defaultKeyPair.public as RSAPublicKey)
                    .build()
        }

        val withClockSkew: OAuth2TokenValidator<Jwt> = createOAuth2TokenValidator()
        decoder.setJwtValidator(withClockSkew)

        val converter = createJwtClaimSetConverter()
        decoder.setClaimSetConverter(converter)

        configurer.decoder(decoder)

        return configurer
    }

    private fun createOAuth2TokenValidator(): OAuth2TokenValidator<Jwt> {
        val withClockSkew: OAuth2TokenValidator<Jwt> = DelegatingOAuth2TokenValidator(
                JwtTimestampValidator(Duration.ofSeconds(60)))


        return withClockSkew
    }

    private fun createJwtClaimSetConverter(): MappedJwtClaimSetConverter {
        val collectionStringConverter = getConverter(
                TypeDescriptor.collection(MutableCollection::class.java, STRING_TYPE_DESCRIPTOR))

        val converter = MappedJwtClaimSetConverter
                .withDefaults(mapOf(
                        Constants.CLAIM_TWO_FACTOR to getConverter(BOOL_TYPE_DESCRIPTOR),
                        Constants.CLAIM_USER_ID to getConverter(STRING_TYPE_DESCRIPTOR),
                        Constants.CLAIM_ROLES to collectionStringConverter
                ))
        return converter
    }

    override fun configure(http: HttpSecurity) {
        http
                .authorizeRequests { authorize ->
                    authorize
                            .expressionHandler(OAuth2TwoFactorSecurityExpressionHandler(http))
                            .also {
                                this.resourceConfigurers.orderedStream().forEach { c ->
                                    c.configure(it)
                                }
                            }
                            .anyRequest().authenticated()
                }
                .oauth2ResourceServer { obj ->
                    obj.jwt().also {
                        this.applyJwtConfiguration(it)
                    }
                }
    }
}