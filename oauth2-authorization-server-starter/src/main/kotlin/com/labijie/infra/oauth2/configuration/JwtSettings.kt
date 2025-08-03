package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.NestedConfigurationProperty


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
data class JwtSettings(
    @NestedConfigurationProperty
    val rsa: RSASettings = RSASettings()
)

data class RSASettings(
    var privateKey: String = "",
    var publicKey: String = ""
)
