/**
 * @author Anders Xiao
 * @date 2025-06-19
 */

package com.labijie.dummy

import com.labijie.infra.oauth2.resource.IResourceAuthorizationConfigurer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer
import org.springframework.stereotype.Component
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Component
class ResourceTestConfigure : WebMvcConfigurer {

    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/**")
            .allowedOrigins("*")
            .allowedMethods("*")
            .maxAge(3600)
            .allowedHeaders("*")
    }
}


class R : IResourceAuthorizationConfigurer {
    override fun configure(registry: AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry) {
        val r = registry.requestMatchers("/endpoint")
        r.hasAnyRole()
    }

}