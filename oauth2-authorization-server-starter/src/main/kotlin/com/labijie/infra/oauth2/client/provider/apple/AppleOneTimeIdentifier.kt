/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/19
 *
 */
package com.labijie.infra.oauth2.client.provider.apple

data class AppleOneTimeIdentifier(
    var name: String = "",
    var email: String = ""
)