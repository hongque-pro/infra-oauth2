package com.labijie.infra.oauth2.configuration

import java.time.Duration

class DefaultClientProperties {
    var clientId: String = "app"
    var secret: String = "!QAZ@WSX"
    var reuseRefreshToken: Boolean = true
    var accessTokenExpiration: Duration = Duration.ofHours(1)
    var refreshTokenExpiration: Duration = Duration.ofDays(7)
    var enabled: Boolean = true
}