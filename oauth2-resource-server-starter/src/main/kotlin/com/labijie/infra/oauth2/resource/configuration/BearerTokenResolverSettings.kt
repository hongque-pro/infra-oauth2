/**
 * @author Anders Xiao
 * @date 2024-06-19
 */
package com.labijie.infra.oauth2.resource.configuration


class BearerTokenResolverSettings {
    var allowCookieName: String? = null
    var allowFormEncodedBodyParameter: Boolean = false
    var allowUriQueryParameter: Boolean = false
}