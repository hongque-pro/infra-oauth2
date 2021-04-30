package com.labijie.infra.oauth2.resource.token

import com.labijie.infra.oauth2.Constants
import org.springframework.core.convert.converter.Converter
import org.springframework.core.log.LogMessage
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.util.StringUtils
import java.util.*

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-30 21:13
 * @Description:
 */
class DefaultJwtGrantedAuthoritiesConverter : Converter<Jwt, MutableCollection<GrantedAuthority>> {
    private val innerConverter = JwtGrantedAuthoritiesConverter()

    override fun convert(source: Jwt): MutableCollection<GrantedAuthority>? {
        //SCOPE
        val collection = innerConverter.convert(source) ?: mutableListOf()
        //ROLE
        val roles = getRoleAuthorities(source)
        return collection.apply {
            addAll(roles.map { SimpleGrantedAuthority(it) })
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun getRoleAuthorities(jwt: Jwt): Collection<String> {
        val authorities = jwt.getClaim<Any>(Constants.CLAIM_AUTHORITIES)
        if (authorities is String) {
            return if (StringUtils.hasText(authorities)) {
                authorities.split(" ".toRegex())
            } else emptyList()
        }

        return (authorities as? Collection<String>) ?: emptyList()
    }
}