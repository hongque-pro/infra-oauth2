/**
 * @author Anders Xiao
 * @date 2024-06-14
 */
package com.labijie.infra.oauth2.component

import com.fasterxml.jackson.databind.ObjectMapper
import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.serialization.jackson.AccessTokenJacksonModule
import org.springframework.beans.factory.config.BeanPostProcessor


class OAuth2ObjectMapperProcessor : BeanPostProcessor {
    override fun postProcessAfterInitialization(bean: Any, beanName: String): Any? {
        val mapper = bean as? ObjectMapper
        if(mapper != null) {
            if(mapper != JacksonHelper.defaultObjectMapper && mapper != JacksonHelper.webCompatibilityMapper) {
                mapper.registerModules(AccessTokenJacksonModule())
            }
        }
        return bean
    }
}