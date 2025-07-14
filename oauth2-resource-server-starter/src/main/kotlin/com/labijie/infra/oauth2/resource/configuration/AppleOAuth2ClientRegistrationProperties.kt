package com.labijie.infra.oauth2.resource.configuration

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
@ConfigurationProperties("spring.security.oauth2.client.registration.apple")
class AppleOAuth2ClientRegistrationProperties {
    var secretValiditySeconds = 30
    var teamId: String = ""
    var keyId: String = ""
    var privateRsaKey: String = ""
}