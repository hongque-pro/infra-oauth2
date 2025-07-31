package com.labijie.infra.oauth2.client

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/23
 *
 */
object OAuth2ClientErrorCodes {
    const val INVALID_OAUTH2_CLIENT_PROVIDER = "invalid_oauth2_client_provider"
    const val INVALID_OIDC_TOKEN = "invalid_oidc_token"
    const val INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response"
    const val OAUTH2_ACCOUNT_NOT_REGISTERED = "oauth2_account_not_registered"
    const val OAUTH2_ACCOUNT_LINKED_ANOTHER_USER = "oauth2_account_linked_another_user"
    const val OAUTH2_PROVIDER_ALREADY_LINKED = "oauth2_provider_already_linked"
}