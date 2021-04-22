package com.labijie.infra.oauth2.token

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.Constants.CLAIM_TWO_FACTOR
import com.labijie.infra.oauth2.Constants.CLAIM_USER_ID
import com.labijie.infra.oauth2.Constants.CLAIM_USER_NAME
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import com.labijie.infra.oauth2.copyAttributesTo
import com.labijie.infra.oauth2.isWellKnownClaim
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 */
object TwoFactorAuthenticationConverter : DefaultUserAuthenticationConverter() {

    init {
        this.setUserClaimName(Constants.CLAIM_USER_NAME)
    }

    override fun convertUserAuthentication(authentication: Authentication): MutableMap<String, Any> {
        @Suppress("UNCHECKED_CAST")
        val details = super.convertUserAuthentication(authentication) as MutableMap<String, Any>


        val map = authentication.details as? Map<*, *>
        map?.forEach {
            details[it.key.toString()] = map.getOrDefault(it.key.toString(), "")!!
        }

        val user = authentication.principal as? ITwoFactorUserDetails
        if (user != null) {
            setUserDetails(details, user)
        }

        return details
    }

    fun setUserDetails(details: MutableMap<String, Any>, user: ITwoFactorUserDetails, twoFactorGranted: Boolean? = null) {

        user.getAttachedTokenFields().forEach {
            details[it.key] = it.value
        }

        details[CLAIM_USER_NAME] = user.username
        details[CLAIM_USER_ID] = user.getUserId()

        if (twoFactorGranted != null) {
            details[CLAIM_TWO_FACTOR] = twoFactorGranted
        }
    }

    override fun extractAuthentication(map: MutableMap<String, *>): Authentication {
        val authentication = super.extractAuthentication(map)

        val token = authentication as? AbstractAuthenticationToken
        if (token != null) {
//            val principal = authentication.principal as? ITwoFactorUserDetails
//            if (principal != null) {
//                principal.isTwoFactorGranted = map.getOrDefault(USER_TWO_FACTOR_PROPERTY, "").toString().toBoolean()
//            }
            val details: MutableMap<String, Any> = mutableMapOf()

            @Suppress("UNCHECKED_CAST")
            val attributes = map as Map<String, Any>

            attributes.forEach { (key, _) ->
                if (!isWellKnownClaim(key)) {
                    copyAttributesTo(attributes, key, details)
                }
            }

            copyAttributesTo(attributes, CLAIM_USER_ID, details)
            copyAttributesTo(attributes, CLAIM_TWO_FACTOR, details)

            return token.apply {
                this.details = details
            }
        }
        return authentication
    }


}