package com.labijie.infra.oauth2.token

import com.labijie.infra.oauth2.Constants
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.TokenEnhancer
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
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
        val user = authentication.userAuthentication.principal as? UserDetails

        if(!authentication.authorities.isNullOrEmpty())
        {
            additionalInfo[Constants.ROLES_PROPERTY] = AuthorityUtils.authorityListToSet(authentication.authorities)
        }

        if (user != null) {
            additionalInfo[UserAuthenticationConverter.USERNAME] = user.username
            additionalInfo[Constants.ROLES_PROPERTY] = AuthorityUtils.authorityListToSet(user.authorities)
        }

        val details = authentication.userAuthentication.details as? Map<*, *>
        if (details != null) {
            additionalInfo[Constants.USER_TWO_FACTOR_PROPERTY] = details.getOrDefault(
                Constants.USER_TWO_FACTOR_PROPERTY, "")!!
            additionalInfo[Constants.USER_ID_PROPERTY] = details.getOrDefault(
                Constants.USER_ID_PROPERTY, "")!!

            //附加字段不向前端展示
//            details.filter { kv -> kv.key != null && kv.key.toString().startsWith(Constants.TOKEN_ATTACHED_FIELD_PREFIX)  }.forEach{
//                val key = it.key.toString()!!.removePrefix(Constants.TOKEN_ATTACHED_FIELD_PREFIX)
//                if(!key.isNotBlank() && it.value != null){
//                    additionalInfo[key] = it.value.toString()
//                }
//            }
        }


        result.additionalInformation = additionalInfo

        return result
    }

}