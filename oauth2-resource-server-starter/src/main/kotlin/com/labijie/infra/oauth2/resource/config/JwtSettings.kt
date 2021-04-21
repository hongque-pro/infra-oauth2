package com.labijie.infra.oauth2.resource.config

import java.time.Duration

class JwtSettings {
    var jwkPubKey: String = ""
    var clockSkew: Duration = Duration.ofMinutes(1)
}