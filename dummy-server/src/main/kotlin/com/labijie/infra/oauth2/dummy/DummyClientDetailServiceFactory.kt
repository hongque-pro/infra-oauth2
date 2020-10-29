package com.labijie.infra.oauth2.dummy

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.IClientDetailsServiceFactory
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.client.BaseClientDetails
import org.springframework.stereotype.Component

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 *
 */
@Component
class DummyClientDetailServiceFactory: IClientDetailsServiceFactory {
    override fun createClientDetailsService(): ClientDetailsService {
        return DummyClientDetailService()
    }

    class DummyClientDetailService : ClientDetailsService {
        override fun loadClientByClientId(clientId: String?): ClientDetails {
            val details = BaseClientDetails().apply {
                this.clientId = clientId
                this.clientSecret = "abcdefg"
                this.setAuthorizedGrantTypes(setOf(
                    Constants.GRANT_TYPE_PASSWORD,
                        Constants.GRANT_TYPE_AUTHORIZATION_CODE,
                        Constants.GRANT_TYPE_CLIENT_CREDENTIALS,
                        Constants.GRANT_TYPE_IMPLICIT,
                        Constants.GRANT_TYPE_REFRESH_TOKEN)) //refresh 也是一种 grant_type, 必须支持才能返回 refresh token
                this.setResourceIds(setOf("api", "auth"))
            }
            return  details
        }
    }
}
