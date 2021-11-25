package com.labijie.infra.oauth2.filter

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
object ClientDetailsHolder {
    private val contextHolder = ThreadLocal<RegisteredClient>()

    fun clearContext() {
        contextHolder.remove()
    }

    fun getClient(): RegisteredClient? {
        return contextHolder.get()
    }

    fun setContext(context: RegisteredClient) {
        contextHolder.set(context)
    }
}