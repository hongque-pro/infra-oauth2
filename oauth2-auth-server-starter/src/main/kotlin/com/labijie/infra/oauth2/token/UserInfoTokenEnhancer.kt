package com.labijie.infra.oauth2.token

import com.labijie.infra.oauth2.Constants
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.TokenEnhancer
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter
import java.util.HashMap


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 */
class UserInfoTokenEnhancer : TokenEnhancer {
    override fun enhance(accessToken: OAuth2AccessToken, authentication: OAuth2Authentication): OAuth2AccessToken {
        val result = DefaultOAuth2AccessToken(accessToken)
        val additionalInfo = HashMap<String, Any>()

        if(!authentication.authorities.isNullOrEmpty())
        {
            additionalInfo[Constants.CLAIM_AUTHORITIES] = AuthorityUtils.authorityListToSet(authentication.authorities)
        }



        val details = authentication.userAuthentication.details as? Map<*, *>
        details?.forEach { (key, u) ->
            if (key != null && u != null && key != DefaultAccessTokenConverter.GRANT_TYPE){
                additionalInfo[key.toString()] = u
            }
        }

        val user = authentication.userAuthentication.principal as? UserDetails
        if (user != null) {
            additionalInfo[Constants.CLAIM_USER_NAME] = user.username
        }

        result.additionalInformation = additionalInfo

        return result
    }

}