package com.labijie.infra.oauth2

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet
import net.minidev.json.JSONObject
import net.minidev.json.annotate.JsonIgnore
import org.springframework.security.oauth2.core.oidc.StandardClaimNames

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/25
 *
 */
class StandardOidcUser(
    val provider: String,
    val userId: String,
    @JsonIgnore
    val idToken: SignedJWT? = null,
    var email: String? = null,
    var emailVerified: Boolean? = false,
    var emailHidden: Boolean? = null,
    var picture: String? = null,
    var username: String? = null,
    var registrationId: String? = null,
) {

    companion object {

        const val CLAIM_NAME_PROVIDER = "provider"
        const val CLAIM_NAME_REGISTRATION_ID = "registrationId"
        const val CLAIM_NAME_EMAIL_HIDDEN = "email_hidden"

        fun StandardOidcUser.setInfo(userInfo: StandardOidcUserInfo) {
            if(userInfo.email.isNotBlank()) {
                this.email = userInfo.email
                this.emailHidden = userInfo.emailVerified
                this.emailVerified = userInfo.emailVerified
            }
            if(!userInfo.picture.isNullOrBlank()) {
                this.picture = userInfo.picture
            }
            if(!userInfo.username.isNullOrBlank()) {
                this.username = userInfo.username
            }
        }

        fun StandardOidcUser.getInfo(): StandardOidcUserInfo {
            return StandardOidcUserInfo().also {
                it.username = this.username
                it.email = this.email.orEmpty()
                it.emailVerified = this.emailVerified
                it.emailHidden = this.emailHidden
                it.picture = this.picture
            }
        }

        fun StandardOidcUser.toAttributes(): Map<String, Any> {
            val attributes = mutableMapOf<String, Any>()
            attributes[CLAIM_NAME_PROVIDER] = provider
            attributes[StandardClaimNames.SUB] = userId
            email?.let { attributes[StandardClaimNames.EMAIL] = it }
            username?.let { attributes[StandardClaimNames.NAME] = it }
            emailVerified?.let { attributes[StandardClaimNames.EMAIL_VERIFIED] = it }
            picture?.let { attributes[StandardClaimNames.PICTURE] = it }
            registrationId?.let { attributes[CLAIM_NAME_REGISTRATION_ID] = it }
            emailHidden?.let { attributes[CLAIM_NAME_EMAIL_HIDDEN] = it }

            return attributes
        }

        fun StandardOidcUser.toClaimSet(): ClaimsSet {
            val attributes = toAttributes()
            return ClaimsSet(JSONObject(attributes))
        }

        fun createFromClaimSet(claimsSet: ClaimsSet): StandardOidcUser {
            val userId = claimsSet.getStringClaim(StandardClaimNames.SUB).orEmpty()
            val provider =claimsSet.getStringClaim(CLAIM_NAME_PROVIDER).orEmpty()
            return StandardOidcUser(provider, userId).apply {
                email = claimsSet.getStringClaim(StandardClaimNames.EMAIL)
                emailVerified = claimsSet.getBooleanClaim(StandardClaimNames.EMAIL_VERIFIED)
                username = claimsSet.getStringClaim(StandardClaimNames.NAME)
                picture = claimsSet.getStringClaim(StandardClaimNames.PICTURE)
                registrationId = claimsSet.getStringClaim(CLAIM_NAME_REGISTRATION_ID)
                this.emailHidden = claimsSet.getBooleanClaim(CLAIM_NAME_EMAIL_HIDDEN)
            }
        }
    }
}

data class StandardOidcUserInfo(
    var email: String = "",
    var emailVerified: Boolean? = false,
    var emailHidden: Boolean? = null,
    var picture: String? = null,
    var username: String? = null,
    var nickname: String? = null,
)