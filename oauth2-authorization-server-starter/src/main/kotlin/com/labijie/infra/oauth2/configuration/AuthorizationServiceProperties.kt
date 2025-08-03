/**
 * @author Anders Xiao
 * @date 2023-12-29
 */
package com.labijie.infra.oauth2.configuration


class AuthorizationServiceProperties{
    var provider: String = "caching"
    var cachingRegion: String? = null
}