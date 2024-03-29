package com.labijie.infra.oauth2.configuration

import java.time.Duration

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
class TokenProperties(
        var reuseRefreshToken:Boolean = true,
        var accessTokenExpiration:Duration = Duration.ofHours(1),
        var refreshTokenExpiration:Duration = Duration.ofDays(1),
        var jwt:JwtSettings = JwtSettings()
)