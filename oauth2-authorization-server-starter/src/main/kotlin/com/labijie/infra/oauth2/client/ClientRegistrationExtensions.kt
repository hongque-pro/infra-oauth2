package com.labijie.infra.oauth2.client

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.security.oauth2.client.registration.ClientRegistration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/24
 *
 */

fun ClientRegistration.findProvider(properties: OAuth2ClientProperties): String {

    val currentAuthUri = this.providerDetails.authorizationUri
    val currentTokenUri = this.providerDetails.tokenUri

    val provider = properties.provider.firstNotNullOfOrNull { (name, provider) ->

        if(name.equals(this.registrationId, ignoreCase = true)) {
            name
        }else {
            val matched = provider.tokenUri?.let { currentTokenUri.equals(it, ignoreCase = true) } == true &&
                    provider.authorizationUri?.let { currentAuthUri.equals(it, ignoreCase = true) } == true
            if (matched) name else null
        }
    }

    return provider ?: this.registrationId
}