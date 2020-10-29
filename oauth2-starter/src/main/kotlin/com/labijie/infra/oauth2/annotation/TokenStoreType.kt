package com.labijie.infra.oauth2.annotation

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
enum class TokenStoreType {
    Jwt,
    Redis,
    InMemory,
    Custom
}