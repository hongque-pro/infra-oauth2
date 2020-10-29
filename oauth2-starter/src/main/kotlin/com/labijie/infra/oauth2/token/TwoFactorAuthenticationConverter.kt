package com.labijie.infra.oauth2.token

import com.labijie.infra.oauth2.Constants
import com.labijie.infra.oauth2.Constants.USER_ID_PROPERTY
import com.labijie.infra.oauth2.Constants.USER_TWO_FACTOR_PROPERTY
import com.labijie.infra.oauth2.ITwoFactorUserDetails
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-22
 */
object TwoFactorAuthenticationConverter : DefaultUserAuthenticationConverter() {
    override fun convertUserAuthentication(authentication: Authentication): MutableMap<String, Any> {

        @Suppress("UNCHECKED_CAST")
        val details = super.convertUserAuthentication(authentication) as MutableMap<String, Any>



        val map = authentication.details as? Map<*,*>
        if(map != null ) {
            if(map.containsKey(USER_TWO_FACTOR_PROPERTY)) {
                details[USER_TWO_FACTOR_PROPERTY] = map.getOrDefault(USER_TWO_FACTOR_PROPERTY, true)!!
            }
            if(map.containsKey(USER_ID_PROPERTY)) {
                details[USER_ID_PROPERTY] = map.getOrDefault(USER_ID_PROPERTY, "")!!
            }
            map.filter { kv -> kv.key != null && kv.key.toString().startsWith(Constants.TOKEN_ATTACHED_FIELD_PREFIX) && kv.value != null }.forEach {
                details[it.key.toString()] = map.getOrDefault(it.key.toString(), "")!!
            }
        }

        val user = authentication.principal as? ITwoFactorUserDetails
        if(user != null) {
            details[UserAuthenticationConverter.USERNAME] = user.username
            details[USER_ID_PROPERTY] = user.getUserId()
            //details[USER_TWO_FACTOR_PROPERTY] = user.isTwoFactorEnabled()

            user.getAttachedTokenFields().forEach {
                details["${Constants.TOKEN_ATTACHED_FIELD_PREFIX}${it.key}"] = it.value
            }
        }

        return details
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

            attributes.filter { kv->kv.key.startsWith(Constants.TOKEN_ATTACHED_FIELD_PREFIX) }.forEach { (key, _) ->
                copyTo(attributes, key, details)
            }

            copyTo(attributes, USER_ID_PROPERTY, details)
            copyTo(attributes, USER_TWO_FACTOR_PROPERTY, details)

            return token.apply {
                this.details = details
            }
        }
        return authentication
    }

    private fun copyTo(source: Map<String, Any>, key: String, destination: MutableMap<String, Any>) {
        val value = source.getOrDefault(key, "").toString()
        if (!value.isBlank()) {
            if (value == "true" || value == "false") {
                destination[key] = value.toBoolean()
            } else {
                destination[key] = value
            }
        }
    }
}