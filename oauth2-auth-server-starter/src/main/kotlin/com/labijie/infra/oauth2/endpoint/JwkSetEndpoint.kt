package com.labijie.infra.oauth2.endpoint

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.EndpointErrors
import com.labijie.infra.oauth2.RsaUtils
import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.oauth2.configuration.TokenStoreType
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseBody


/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-22 10:07
 * @Description:
 * support any [JWK Set] (https://tools.ietf.org/html/rfc7517#section-5) endpoint.
 */
@FrameworkEndpoint
internal class JwkSetEndpoint(private val serverProperties: OAuth2ServerProperties) {

    @ResponseBody
    @GetMapping(Constants.DEFAULT_JWK_SET_ENDPOINT_PATH)
    fun jwkSet(): Any {
        return if (serverProperties.token.store == TokenStoreType.Jwt){
            val pubKey = RsaUtils.getPublicKey(serverProperties.token.jwt.rsa.publicKey)
            val key = RSAKey.Builder(pubKey).build()
            return JWKSet(key).toJSONObject()
        }else {
            OAuth2Exception.create(EndpointErrors.INVALID_TOKEN_TYPE, "The token type of the authorization server is not jwt")
        }
    }
}