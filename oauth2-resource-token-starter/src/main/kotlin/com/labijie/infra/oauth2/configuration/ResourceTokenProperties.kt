package com.labijie.infra.oauth2.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-10
 */
@ConfigurationProperties("security.oauth2.resource")
class ResourceTokenProperties {
    var tokenCacheRegion:String = ""
    var tokenCachePrefix:String = "token-"
    var tokenCacheEnabled:Boolean = true
    var tokenCacheTimeout: Duration? = null
}