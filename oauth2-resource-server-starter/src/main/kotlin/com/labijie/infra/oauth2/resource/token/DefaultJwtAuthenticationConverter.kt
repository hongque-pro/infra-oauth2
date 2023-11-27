package com.labijie.infra.oauth2.resource.token

import com.labijie.infra.oauth2.OAuth2Constants
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-30 21:11
 * @Description:
 */
class DefaultJwtAuthenticationConverter : JwtAuthenticationConverter(){
    init {
        super.setPrincipalClaimName(OAuth2Constants.CLAIM_USER_NAME)
        super.setJwtGrantedAuthoritiesConverter(DefaultJwtGrantedAuthoritiesConverter())
    }
}