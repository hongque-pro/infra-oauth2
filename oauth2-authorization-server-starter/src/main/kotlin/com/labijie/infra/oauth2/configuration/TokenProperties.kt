package com.labijie.infra.oauth2.configuration

import java.time.Duration

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
class TokenProperties(
        var jwt:JwtSettings = JwtSettings()
)