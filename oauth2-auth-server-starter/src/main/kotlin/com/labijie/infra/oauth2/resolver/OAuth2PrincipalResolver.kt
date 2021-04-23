package com.labijie.infra.oauth2.resolver

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.IPrincipalResolver
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.isWellKnownClaim
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.OAuth2Authentication

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 21:03
 * @Description:
 */

class OAuth2PrincipalResolver : IPrincipalResolver {
    override fun getOrder(): Int = 9999

    override fun support(authentication: Authentication): Boolean {
        return authentication is OAuth2Authentication &&  authentication.details != null && authentication.details is Map<*, *> && !(authentication.details as Map<*, *>).isEmpty()
    }

    override fun resolvePrincipal(authentication: Authentication): TwoFactorPrincipal {
        val userAuthentication = if (authentication is OAuth2Authentication){
            authentication.userAuthentication //带 token 请求时
        }else{
            authentication //登录成功时
        }

        val map = userAuthentication.details as? Map<*,*> ?: throw BadCredentialsException("Current authentication dose not contains any user details")


        val attachments = mutableMapOf<String, String>()
        map.filter { kv ->
            kv.key != null &&
                    kv.value != null &&
                    kv.key is String &&
                    !isWellKnownClaim(kv.key.toString())
        }.forEach {
            attachments[it.key.toString()] = it.value.toString()
        }

        return TwoFactorPrincipal(
                map.getOrDefault(Constants.CLAIM_USER_ID, "").toString(),
                authentication.name,
                isTwoFactorGranted = map.getOrDefault(Constants.CLAIM_TWO_FACTOR, "false").toString().toBoolean(),
                authorities = authentication.authorities.toMutableList(),
                attachedFields = attachments
        )
    }
}