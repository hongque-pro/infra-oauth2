/**
 * @author Anders Xiao
 * @date 2024-06-19
 */
package com.labijie.infra.oauth2.resource.component


internal class PlainTextCookieDecoder : IOAuth2TokenCookieDecoder {
    override fun decode(cookieValue: String?): String? {
        return cookieValue
    }
}