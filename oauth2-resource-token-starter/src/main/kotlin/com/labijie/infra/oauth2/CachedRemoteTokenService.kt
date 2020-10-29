package com.labijie.infra.oauth2

import com.labijie.infra.oauth2.configuration.ResourceTokenProperties
import com.labijie.infra.oauth2.token.TwoFactorAuthenticationConverter
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.http.client.ClientHttpResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.AccessTokenConverter
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.util.Base64Utils
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.DefaultResponseErrorHandler
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate
import java.io.IOException
import java.io.UnsupportedEncodingException
import kotlin.jvm.Throws

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-10
 */
class CachedRemoteTokenService(
    private val tokenCache: ITokenCache,
    private val resourceTokenProperties: ResourceTokenProperties,
    private val resourceServerProperties: ResourceServerProperties) : ResourceServerTokenServices {

    protected val logger = LoggerFactory.getLogger(CachedRemoteTokenService::class.java)

    var restTemplate: RestOperations = RestTemplate()

    var tokenName = "token"

    var tokenConverter: AccessTokenConverter = DefaultAccessTokenConverter().apply {
        this.setUserTokenConverter(TwoFactorAuthenticationConverter)
    }

    init {
        (restTemplate as RestTemplate).errorHandler = object : DefaultResponseErrorHandler() {
            @Throws(IOException::class)
            override// Ignore 400
            fun handleError(response: ClientHttpResponse) {
                if ((response.rawStatusCode / 100) == 4) {
                    super.handleError(response)
                }
            }
        }
    }

    @Throws(AuthenticationException::class, InvalidTokenException::class)
    override fun loadAuthentication(accessToken: String): OAuth2Authentication {

        val formData = LinkedMultiValueMap<String, String>()
        formData.add(tokenName, accessToken)
        val headers = HttpHeaders()
        headers.set("Authorization", getAuthorizationHeader(this.resourceServerProperties.clientId, this.resourceServerProperties.clientSecret))
        val map = requestToken(this.resourceServerProperties.tokenInfoUri, formData, headers)

        if (map!!.containsKey("error")) {
            if (logger.isDebugEnabled) {
                logger.debug("check_token returned error: " + map["error"])
            }
            throw InvalidTokenException(accessToken)
        }

        // gh-838
        if (java.lang.Boolean.TRUE != map["active"]) {
            logger.debug("check_token returned active attribute: " + map["active"])
            throw InvalidTokenException(accessToken)
        }

        return tokenConverter.extractAuthentication(map)
    }

    override fun readAccessToken(accessToken: String): OAuth2AccessToken {
        throw UnsupportedOperationException("Not supported: read access token")
    }

    private fun getAuthorizationHeader(clientId: String?, clientSecret: String?): String {

        if (clientId == null || clientSecret == null) {
            logger.warn("Null Client ID or Client Secret detected. Endpoint that requires authentication will reject request with 401 error.")
        }

        val creds = String.format("%s:%s", clientId, clientSecret)
        try {
            val secretKey = Base64Utils.encodeToString(creds.toByteArray(Charsets.UTF_8))
            return "Basic $secretKey"
        } catch (e: UnsupportedEncodingException) {
            throw IllegalStateException("Could not convert String")
        }

    }

    protected fun postForMap(path: String, formData: MultiValueMap<String, String>, headers: HttpHeaders): Map<String, String>? {
        if (headers.contentType == null) {
            headers.contentType = MediaType.APPLICATION_FORM_URLENCODED
        }

        @Suppress("UNCHECKED_CAST")
        val map = restTemplate.exchange(path,
                HttpMethod.POST,
                HttpEntity(formData, headers), Map::class.java).body as? Map<String, String>

        if (logger.isDebugEnabled) {
            logger.debug("remote token info: ${map?.toList()?.joinToString { "${it.first}=${it.second}" }}")
        }
        return map
    }

    private fun requestToken(path: String, formData: MultiValueMap<String, String>, headers: HttpHeaders): Map<String, Any>? {
        val token = formData[this.tokenName]?.firstOrNull()
        if (!token.isNullOrBlank()) {
            val key = "${resourceTokenProperties.tokenCachePrefix}$token"

            var map = tokenCache.get(key, this.resourceTokenProperties.tokenCacheRegion)

            if (map == null) {
                map = this.postForMap(path, formData, headers)
                if(map != null) {
                    val expMills = getCacheTimeoutMills(map)
                    if(expMills > 1000) {
                        tokenCache.set(key, map, this.resourceTokenProperties.tokenCacheRegion, expMills)
                    }
                }else{
                    return map
                }
            }
            return map
        }
        return this.postForMap(path, formData, headers)
    }

    private fun getCacheTimeoutMills(token:Map<String, Any>): Long {
        if(this.resourceTokenProperties.tokenCacheTimeout != null){
            return this.resourceTokenProperties.tokenCacheTimeout!!.toMillis()
        }
        val exp = token.getOrDefault("exp", "").toString()
        if (!exp.isBlank()) {
            return try {
                exp.toLong() * 1000 - System.currentTimeMillis()
            } catch (e: NumberFormatException) {
                -1L
            }
        }
        return -1L
    }

}