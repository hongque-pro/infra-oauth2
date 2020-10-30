package com.labijie.infra.oauth2.testing.component

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.IClientDetailsServiceFactory
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.client.BaseClientDetails
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService
import org.springframework.stereotype.Component

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 *
 */
class TestingClientDetailServiceFactory : IClientDetailsServiceFactory {

    override fun createClientDetailsService(): ClientDetailsService {
        return DummyClientDetailService()
    }

    class DummyClientDetailService : ClientDetailsService {
        override fun loadClientByClientId(clientId: String?): ClientDetails? {
            if(clientId != OAuth2TestingUtils.TestClientId){
                return null
            }

            val details = BaseClientDetails().apply {
                this.clientId = clientId
                this.clientSecret = OAuth2TestingUtils.TestClientSecret //OAuth2TestingUtils.passwordEncoder.encode("abcdefg")
                this.setAuthorizedGrantTypes(setOf(
                        Constants.GRANT_TYPE_PASSWORD,
                        Constants.GRANT_TYPE_AUTHORIZATION_CODE,
                        Constants.GRANT_TYPE_CLIENT_CREDENTIALS,
                        Constants.GRANT_TYPE_IMPLICIT,
                        Constants.GRANT_TYPE_REFRESH_TOKEN)) //refresh 也是一种 grant_type, 必须支持才能返回 refresh token
                this.setResourceIds(setOf("api", "auth"))
            }
            return details
        }
    }
}
