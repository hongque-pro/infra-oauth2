package com.labijie.infra.oauth2

import org.springframework.security.oauth2.provider.ClientDetailsService

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 */
interface IClientDetailsServiceFactory {
    fun createClientDetailsService():ClientDetailsService
}