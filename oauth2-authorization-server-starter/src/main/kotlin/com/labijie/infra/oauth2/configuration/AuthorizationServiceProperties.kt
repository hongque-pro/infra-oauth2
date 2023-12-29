/**
 * @author Anders Xiao
 * @date 2023-12-29
 */
package com.labijie.infra.oauth2.configuration


data class AuthorizationServiceProperties(var provider: String = "caching", var cachingRegion: String? = null)