package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.NestedConfigurationProperty

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
class TokenProperties {
        @NestedConfigurationProperty
        var jwt:JwtSettings = JwtSettings()
}