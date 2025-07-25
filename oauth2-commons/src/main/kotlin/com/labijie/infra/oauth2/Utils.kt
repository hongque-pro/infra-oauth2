package com.labijie.infra.oauth2

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import org.bouncycastle.asn1.x509.ObjectDigestInfo.publicKey
import java.security.interfaces.RSAPublicKey


/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 19:34
 * @Description:
 */

fun copyAttributesTo(source: Map<String, Any>, key: String, destination: MutableMap<String, Any>) {
    val value = source.getOrDefault(key, "").toString()
    if (!value.isBlank()) {
        if (value == "true" || value == "false") {
            destination[key] = value.toBoolean()
        } else {
            destination[key] = value
        }
    }
}

val ALL_JWK_SELECTOR by lazy {
    val jwkMatcher = JWKMatcher.Builder()
        .build()
    JWKSelector(jwkMatcher)
}

fun <T : SecurityContext> JWKSource<T>.getAll() : JWKSet {
    val list = this.get(ALL_JWK_SELECTOR, null)
    return JWKSet(list)
}

fun <T : SecurityContext> JWKSource<T>.getRSAKey(keyId: String) : RSAKey? {

    val jwkMatcher = JWKMatcher.Builder()
        .keyID(keyId)
        .build()
    val selector = JWKSelector(jwkMatcher)

    val rsaKey = (this.get(selector, null).firstOrNull() as? RSAKey)

    return rsaKey
}





