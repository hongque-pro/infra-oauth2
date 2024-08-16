/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2



class AccessToken {
    var accessToken: String = ""

    var expiresIn: Long = 0

    var tokenType: String = ""

    var scope: String? = null

    var twoFactorGranted: Boolean? = null

    var userId: String = ""

    var username: String = ""

    var refreshToken: String? = null

    var authorities: MutableList<String> = mutableListOf()

    var details: HashMap<String, Any> = hashMapOf()
}