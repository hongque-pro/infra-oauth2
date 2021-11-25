package com.labijie.infra.oauth2.configuration


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
data class JwtSettings(var rsa: RSASettings = RSASettings())

data class RSASettings(var privateKey: String = "", var publicKey: String = "")
