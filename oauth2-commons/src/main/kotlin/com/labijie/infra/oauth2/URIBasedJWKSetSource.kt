package com.labijie.infra.oauth2

import com.nimbusds.jose.jwk.source.JWKSetRetrievalException
import com.nimbusds.jose.jwk.source.URLBasedJWKSetSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.Resource
import com.nimbusds.jose.util.ResourceRetriever
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.web.client.RestClient
import org.springframework.web.client.toEntity
import java.net.URI
import java.net.URL

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
class URIBasedJWKSetSource<T : SecurityContext>(
    restClient: RestClient,
    uri: URI,
    httpMethod: HttpMethod
) : URLBasedJWKSetSource<T>(uri.toURL(), ResetClientResourceRetriever(restClient, httpMethod)) {

    class ResetClientResourceRetriever(
        private val restClient: RestClient,
        private val httpMethod: HttpMethod = HttpMethod.GET
    ) : ResourceRetriever {
        override fun retrieveResource(url: URL): Resource? {
            val uri = URI.create(url.toString())
            val response = restClient.method(httpMethod)
                .uri(uri)
                .retrieve()
                .toEntity<String>()

            if (!response.statusCode.is2xxSuccessful) {
                throw JWKSetRetrievalException("Couldn't retrieve JWK set from URL (method: httpMethod): $uri, http status: ${response.statusCode.value()}", null)
            }
            return Resource(response.body, (response.headers.contentType ?: MediaType.APPLICATION_JSON)?.toString())
        }
    }
}