package com.labijie.infra.oauth2.client

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.labijie.infra.oauth2.AccessToken
import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.serialization.jackson.OAuth2CommonsJacksonModule
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient
import org.springframework.web.client.toEntity
import java.net.URI

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/14
 *
 */
object RestClientExtensions {
    private val mapper = ObjectMapper().apply {
        registerModules(OAuth2CommonsJacksonModule.INSTANCE)
    }

    fun RestClient.postOAuth2SignOut(
        accessToken: String,
        clientId: String,
        clientSecret: String,
        oauth2ServerBaseUrl: String = "http://localhost:8080",
        oauth2ServerTokenPath: String = OAuth2Utils.DefaultServerEndpoints.TOKEN_REVOCATION
    ): ResponseEntity<Void> {
        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("token", accessToken)
        params.add("token_type_hint", "Bearer")

        val base = URI.create(oauth2ServerBaseUrl)

        return try {
            this.post().uri {
                it.scheme(base.scheme)
                it.host(base.host)
                it.port(base.port)
                it.path( oauth2ServerTokenPath)
                    .queryParam("token", accessToken)
                    .queryParam("token_type_hint", "Bearer")
                    .build()
            }
            .headers {
                it.setBasicAuth(clientId, clientSecret)
            }
            .accept(MediaType.APPLICATION_JSON)
            .retrieve()
            .toEntity<Void>()
        } catch (e: HttpClientErrorException) {
            ResponseEntity<Void>.status(e.statusCode).build()
        }
    }

    fun RestClient.postOAuth2SignIn(
        username: String,
        password: String,
        clientId: String,
        clientSecret: String,
        oauth2ServerBaseUrl: String = "http://localhost:8080",
        oauth2ServerTokenPath: String = OAuth2Utils.DefaultServerEndpoints.TOKEN
    ): ResponseEntity<AccessToken> {

        val params: MultiValueMap<String, String> = LinkedMultiValueMap()
        params.add("grant_type", "password")
        params.add("username", username)
        params.add("password", password)

        val base = URI.create(oauth2ServerBaseUrl)

        val resp = try {
            this.post().uri {
                it.scheme(base.scheme)
                it.host(base.host)
                it.port(base.port)
                it.path( oauth2ServerTokenPath)
                    .queryParam("grant_type", "password")
                    .queryParam("username", username)
                    .queryParam("password", password)
                    .build()
            }
            .headers {
                it.setBasicAuth(clientId, clientSecret)
            }
            .accept(MediaType.APPLICATION_JSON)
            .retrieve()
            .toEntity<String>()
        } catch (e: HttpClientErrorException) {
            ResponseEntity<String>.status(e.statusCode).body(e.getResponseBodyAsString(Charsets.UTF_8))
        }

        return resp.let {
            val token = it.body?.let { body-> mapper.readValue<AccessToken>(body) }
            ResponseEntity(token,it.headers, it.statusCode)
        }
    }


}