package com.labijie.infra.oauth2

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

    const val USER_TWO_FACTOR_PROPERTY = "two_factor_granted"
    const val TOKEN_ATTACHED_FIELD_PREFIX = "__att_"
    const val USER_ID_PROPERTY = "user_id"
    const val ROLES_PROPERTY = "roles"
}