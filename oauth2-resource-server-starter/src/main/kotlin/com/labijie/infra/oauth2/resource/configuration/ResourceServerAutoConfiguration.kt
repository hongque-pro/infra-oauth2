package com.labijie.infra.oauth2.resource.configuration

import com.labijie.infra.oauth2.ITokenIntrospectParser
import com.labijie.infra.oauth2.OAuth2Constants
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.configuration.InfraOAuth2CommonsAutoConfiguration
import com.labijie.infra.oauth2.resource.ActuatorAuthorizationConfigurer
import com.labijie.infra.oauth2.resource.LocalOpaqueTokenIntrospector
import com.labijie.infra.oauth2.resource.component.IResourceServerSecretsStore
import com.labijie.infra.oauth2.resource.resolver.BearTokenPrincipalResolver
import com.labijie.infra.oauth2.resource.resolver.BearTokenValueResolver
import com.labijie.infra.oauth2.resource.token.DefaultJwtAuthenticationConverter
import com.labijie.infra.utils.ifNullOrBlank
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.TypeDescriptor
import org.springframework.core.convert.converter.Converter
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.converter.ClaimConversionService
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import java.io.IOException
import java.security.interfaces.RSAPublicKey


@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ResourceServerProperties::class, OAuth2ResourceServerProperties::class)
@AutoConfigureAfter(InfraOAuth2CommonsAutoConfiguration::class)
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration::class)
@AutoConfigureOrder(1)
class ResourceServerAutoConfiguration(
    private val resourceServerProperties: ResourceServerProperties,
) {


    companion object {
        private val OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Any::class.java)
        private val STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String::class.java)
        private val BOOL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean::class.java)
        private val logger by lazy {
            LoggerFactory.getLogger(ResourceServerAutoConfiguration::class.java)
        }

        private fun getConverter(targetDescriptor: TypeDescriptor): Converter<Any, *> {
            return Converter { source: Any? ->
                if (source == null) null else
                    ClaimConversionService.getSharedInstance().convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor)
            }
        }

//        private fun HttpSecurity.getAuthorizeHttpRequestsConfigurer(): AuthorizeHttpRequestsConfigurer<HttpSecurity>? {
//            val context: ApplicationContext = getSharedObject(ApplicationContext::class.java)
//            val c = AuthorizeHttpRequestsConfigurer<HttpSecurity>(context)
//            return getConfigurer(c::class.java)
//        }
    }

    private var defaultPubKeyUsed = false


    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationConverter::class)
    fun defaultJwtAuthenticationConverter(): DefaultJwtAuthenticationConverter {
        return DefaultJwtAuthenticationConverter()
    }

    @Bean
    fun bearTokenValueResolver(): BearTokenValueResolver {
        return BearTokenValueResolver()
    }

    @Bean
    fun bearTokenPrincipalResolver(): BearTokenPrincipalResolver {
        return BearTokenPrincipalResolver()
    }


    @Bean
    @ConditionalOnMissingBean(OpaqueTokenIntrospector::class)
    @ConditionalOnBean(ITokenIntrospectParser::class)
    fun localOpaqueTokenIntrospector(tokenIntrospectParser: ITokenIntrospectParser): LocalOpaqueTokenIntrospector {
        return LocalOpaqueTokenIntrospector(tokenIntrospectParser)
    }


    @Bean
    @ConditionalOnClass(name = ["org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"])
    fun actuatorConfigure(): ActuatorAuthorizationConfigurer {
        return ActuatorAuthorizationConfigurer()
    }

    private fun createOAuth2TokenValidator(issuerUri: String?): OAuth2TokenValidator<Jwt> {
        val validators = mutableListOf<OAuth2TokenValidator<Jwt>>(
            JwtTimestampValidator(resourceServerProperties.jwt.clockSkew)
        )
        issuerUri?.let {
            validators.add(JwtIssuerValidator(issuerUri))
        }

        return DelegatingOAuth2TokenValidator(*validators.toTypedArray())
    }

    private fun createJwtClaimSetConverter(): MappedJwtClaimSetConverter {
        val collectionStringConverter = getConverter(
            TypeDescriptor.collection(MutableCollection::class.java, STRING_TYPE_DESCRIPTOR)
        )

        return MappedJwtClaimSetConverter
            .withDefaults(
                mapOf(
                    OAuth2Constants.CLAIM_USER_NAME to getConverter(STRING_TYPE_DESCRIPTOR),
                    OAuth2Constants.CLAIM_TWO_FACTOR to getConverter(BOOL_TYPE_DESCRIPTOR),
                    OAuth2Constants.CLAIM_USER_ID to getConverter(STRING_TYPE_DESCRIPTOR),
                    OAuth2Constants.CLAIM_AUTHORITIES to collectionStringConverter
                )
            )
    }

    private  var appliedIssuer: String? = null

    @Bean
    @ConditionalOnMissingBean(JwtDecoder::class)
    fun jwtDecoder(
        @Autowired(required = false)
        secretsStore: IResourceServerSecretsStore?,
        springResourceProperties: OAuth2ResourceServerProperties,
        serverProperties: ResourceServerProperties
    ): JwtDecoder {

        val decoder = if (secretsStore != null) {

            val pubKey = RsaUtils.getPublicKey(secretsStore.getRsaPublicKey(serverProperties))
            NimbusJwtDecoder.withPublicKey(pubKey)
                .build()
        } else if (resourceServerProperties.jwt.rsaPubKey.isNotBlank()) {

            val rsaPubKey = OAuth2Utils.loadContent(resourceServerProperties.jwt.rsaPubKey, RsaUtils::getPublicKey)
                ?: throw IOException("${ResourceServerProperties.PUBLIC_KEY_CONFIG_PATH} is not an pem content or file/resource path.")

            NimbusJwtDecoder.withPublicKey(rsaPubKey)
                .build()
        } else {
            defaultPubKeyUsed = true
            NimbusJwtDecoder.withPublicKey(RsaUtils.defaultKeyPair.public as RSAPublicKey)
                .build()
        }

        val validator: OAuth2TokenValidator<Jwt> = createOAuth2TokenValidator(springResourceProperties.jwt.issuerUri)
        decoder.setJwtValidator(validator)

        val converter = createJwtClaimSetConverter()
        decoder.setClaimSetConverter(converter)

        appliedIssuer = springResourceProperties.jwt.issuerUri.orEmpty()
        logger.info("OAuth2 resource server jwt decoder applied (issuer: ${springResourceProperties.jwt.issuerUri.ifNullOrBlank { "<empty>" }}).")

        return decoder
    }


    @Bean
    fun afterOauth2ResourceServerRunner(): CommandLineRunner {
        return CommandLineRunner {
            val info = StringBuilder()
                .appendLine("OAuth2 resource server started.")
                .apply {
                    appliedIssuer?.let {
                        appendLine("OAuth2 issuer: ${it.ifNullOrBlank { "<empty>" }}\n")
                    }
                }
            logger.warn(info.toString())


            if (defaultPubKeyUsed) {
                val warn = StringBuilder()
                    .appendLine("The oauth2 resource server uses a built-in public key for token decoding, which can be a security issue.")
                    .appendLine("Configure one of following properties can be fix this warning:")
                    .appendLine("Configure one of following properties can be fix this warning:")
                    .appendLine("  1. ${ResourceServerProperties.PUBLIC_KEY_CONFIG_PATH} (pem content/file path/classpath resource)")
                    .appendLine("  2. spring.security.oauth2.resourceserver.jwt.public-key-location (resource path)")
                    .appendLine("  3. spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
                    .appendLine("  4. implement a bean that inherits from IResourceServerSecretsStore interface")
                    .toString()
                logger.warn(warn)
            }
        }
    }
}