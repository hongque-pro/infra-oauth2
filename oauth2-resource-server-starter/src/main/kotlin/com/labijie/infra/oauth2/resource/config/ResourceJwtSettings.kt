package com.labijie.infra.oauth2.resource.config

import java.time.Duration

class ResourceJwtSettings {
    var rsaPubKey: String = ""
    var clockSkew: Duration = Duration.ofMinutes(1)
}