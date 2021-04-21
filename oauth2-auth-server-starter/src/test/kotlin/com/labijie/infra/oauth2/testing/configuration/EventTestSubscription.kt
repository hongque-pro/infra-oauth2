package com.labijie.infra.oauth2.testing.configuration

import com.labijie.infra.oauth2.events.UserSignedInEvent
import org.springframework.context.ApplicationListener
import java.util.concurrent.atomic.AtomicInteger

class EventTestSubscription : ApplicationListener<UserSignedInEvent> {
    companion object {
        var fireCount : AtomicInteger = AtomicInteger()
            private set

        fun resetFireCount(){
            fireCount = AtomicInteger()
        }
    }

    override fun onApplicationEvent(event: UserSignedInEvent) {
        fireCount.incrementAndGet()
    }
}