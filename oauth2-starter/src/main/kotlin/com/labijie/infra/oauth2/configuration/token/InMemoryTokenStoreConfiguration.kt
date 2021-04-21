package com.labijie.infra.oauth2.configuration.token

import org.springframework.context.annotation.Bean
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-25
 */
class InMemoryTokenStoreConfiguration {
    @Bean
    fun imMemoryTokenStore(): InMemoryTokenStore {
        return InMemoryTokenStore()
    }
}