package com.labijie.infra.oauth2.client.provider.apple

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/9/19
 *
 */
interface IAppleIdOneTimeStore {
    fun save(key: String, info: AppleOneTimeIdentifier)
    fun get(key: String): AppleOneTimeIdentifier?
}