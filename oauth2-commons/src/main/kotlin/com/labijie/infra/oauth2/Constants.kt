package com.labijie.infra.oauth2

import com.nimbusds.openid.connect.sdk.claims.ClaimType

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 */
object Constants {
    const val GRANT_TYPE_PASSWORD = "password"
    const val GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
    const val GRANT_TYPE_REFRESH_TOKEN = "refresh_token"
    const val GRANT_TYPE_IMPLICIT = "implicit"
    const val GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"

    const val CLAIM_TWO_FACTOR = "two_factor_granted"

    //    const val CLAIM_ATTACHED_FIELD_PREFIX = "__att_"
    const val CLAIM_USER_ID = "user_id"
    const val CLAIM_ROLES = "roles"
    const val CLAIM_AUTHORITIES = "authorities"
    const val CLAIM_USER_NAME = "username"
    const val CLAIM_ISS = "iss"
    const val CLAIM_EXP = "exp"
    const val CLAIM_NBF = "nbf"
    const val CLAIM_IAT = "iat"
    const val CLAIM_SUB = "sub"
    const val CLAIM_AUD = "aud"
    const val CLAIM_JTI = "jti"

}


fun isWellKnownClaim(claimName: String): Boolean {
    return when (claimName) {
        Constants.CLAIM_TWO_FACTOR,
        Constants.CLAIM_USER_ID,
        Constants.CLAIM_AUTHORITIES,
        Constants.CLAIM_USER_NAME -> true
        else -> false
    }
}