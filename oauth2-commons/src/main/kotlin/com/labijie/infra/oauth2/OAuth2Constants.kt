package com.labijie.infra.oauth2

import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 */
object OAuth2Constants {
    const val ENDPOINT_CHECK_TOKEN ="/oauth2/check-token"
    const val UNAUTHORIZED_ENDPOINT ="/oauth2/unauthorized"

    const val CLAIM_TWO_FACTOR = "two_factor_granted"

    const val CLAIM_USER_ID = "user_id"
    const val CLAIM_ROLES = "roles"
    const val CLAIM_AUTHORITIES = "authorities"
    const val CLAIM_SCOPE = OAuth2TokenIntrospectionClaimNames.SCOPE
    const val CLAIM_USER_NAME = OAuth2TokenIntrospectionClaimNames.USERNAME
    const val CLAIM_ISS = OAuth2TokenIntrospectionClaimNames.ISS
    const val CLAIM_EXP = OAuth2TokenIntrospectionClaimNames.EXP
    const val CLAIM_NBF = OAuth2TokenIntrospectionClaimNames.NBF
    const val CLAIM_IAT = OAuth2TokenIntrospectionClaimNames.IAT
    const val CLAIM_SUB = OAuth2TokenIntrospectionClaimNames.SUB
    const val CLAIM_AUD = OAuth2TokenIntrospectionClaimNames.AUD
    const val CLAIM_JTI = OAuth2TokenIntrospectionClaimNames.JTI

    const val SCOPE_AUTHORITY_PREFIX = "SCOPE_"
    const val ROLE_AUTHORITY_PREFIX = "ROLE_"
}

fun isWellKnownClaim(claimName: String): Boolean {
    return when (claimName) {
        OAuth2Constants.CLAIM_TWO_FACTOR,
        OAuth2Constants.CLAIM_USER_ID,
        OAuth2Constants.CLAIM_AUTHORITIES,
        OAuth2Constants.CLAIM_USER_NAME -> true
        else -> false
    }
}