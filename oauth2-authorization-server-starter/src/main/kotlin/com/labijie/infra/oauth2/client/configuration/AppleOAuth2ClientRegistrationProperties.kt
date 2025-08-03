package com.labijie.infra.oauth2.client.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/14
 *
 */
@ConfigurationProperties("spring.security.oauth2.client.registration.apple")
class AppleOAuth2ClientRegistrationProperties {
    var secretValidity = Duration.ofSeconds(30)
    var teamId: String = ""
    var keyId: String = ""
    var privateRsaKey: String = ""

    companion object {
        const val PRIVATE_KEY_PROPERTY_PATH = "spring.security.oauth2.client.registration.apple.private-rsa-key"
    }
}