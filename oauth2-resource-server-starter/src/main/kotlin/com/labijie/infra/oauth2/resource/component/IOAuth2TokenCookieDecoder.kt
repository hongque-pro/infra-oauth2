/**
 * @author Anders Xiao
 * @date 2024-06-19
 */
package com.labijie.infra.oauth2.resource.component


interface IOAuth2TokenCookieDecoder {
    fun decode(cookieValue: String?): String?
}