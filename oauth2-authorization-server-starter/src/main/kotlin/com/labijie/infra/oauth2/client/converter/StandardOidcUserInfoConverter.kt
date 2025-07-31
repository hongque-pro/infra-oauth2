package com.labijie.infra.oauth2.client.converter

import com.labijie.infra.oauth2.StandardOidcUserInfo
import com.labijie.infra.oauth2.client.extension.IOidcUserConverter
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet
import org.springframework.security.oauth2.core.oidc.StandardClaimNames

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/27
 *
 */
object StandardOidcUserInfoConverter : IOidcUserConverter {

    override fun getProvider() = ""

    override fun convert(claimsSet: ClaimsSet): StandardOidcUserInfo {
        return StandardOidcUserInfo().apply {
            val email = claimsSet.getStringClaim(StandardClaimNames.EMAIL).orEmpty()
            if(email.isNotBlank()) {
                this.email = email
                this.emailVerified = true
                //如果没有 EMAIL_VERIFIED ， 表示邮箱被验证
                claimsSet.getBooleanClaim(StandardClaimNames.EMAIL_VERIFIED)?.let {
                    this.emailVerified = it
                }
            }
            claimsSet.getStringClaim(StandardClaimNames.NAME)?.let {
                this.username = it
            }
            claimsSet.getStringClaim(StandardClaimNames.PICTURE)?.let {
                this.picture = it
            }
        }
    }
}