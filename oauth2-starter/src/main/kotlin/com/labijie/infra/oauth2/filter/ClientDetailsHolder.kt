package com.labijie.infra.oauth2.filter

import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.util.Assert

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-11
 */
object ClientDetailsHolder {
    private val contextHolder = ThreadLocal<ClientDetails>()

    fun clearContext() {
        contextHolder.remove()
    }

    fun getClient(): ClientDetails? {
        return contextHolder.get()
    }

    fun setContext(context: ClientDetails) {
        contextHolder.set(context)
    }
}