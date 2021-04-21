package com.labijie.infra.oauth2

import org.springframework.boot.context.event.ApplicationPreparedEvent
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent

/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 21:41
 * @Description:
 */
class OAuth2ApplicationListener : ApplicationListener<ContextRefreshedEvent> {
    override fun onApplicationEvent(event: ContextRefreshedEvent) {
        if(event.applicationContext.parent == null) {
            OAuth2Utils.setApplicationContext(event.applicationContext)
        }
    }
}