package com.labijie.infra.oauth2.configuration

import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier
import java.security.KeyPair

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
data class JwtSettings(var keyType: JwtKeyType = JwtKeyType.Simple,
                       var simpleKey:String = "QWErty654#@!",
                       var rsa: RSASettings = RSASettings())

data class RSASettings(var privateKey: String = "", var publicKey: String = "")

enum class JwtKeyType {
    Simple,RSA
}