package com.labijie.infra.oauth2.configuration

import org.springframework.boot.autoconfigure.condition.ConditionMessage
import org.springframework.boot.autoconfigure.condition.ConditionOutcome
import org.springframework.boot.autoconfigure.condition.SpringBootCondition
import org.springframework.context.annotation.ConditionContext
import org.springframework.core.type.AnnotatedTypeMetadata
import org.springframework.util.StringUtils

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-10
 */
internal class TokenInfoCondition : SpringBootCondition() {

    override fun getMatchOutcome(context: ConditionContext,
                                 metadata: AnnotatedTypeMetadata): ConditionOutcome {
        val message = ConditionMessage
                .forCondition("OAuth TokenInfo Condition")
        val environment = context.environment
        var preferTokenInfo = environment.getProperty(
                "security.oauth2.resource.prefer-token-info", Boolean::class.java)
        if (preferTokenInfo == null) {
            preferTokenInfo = environment
                    .resolvePlaceholders("\${OAUTH2_RESOURCE_PREFERTOKENINFO:true}") == "true"
        }
        val tokenInfoUri = environment
                .getProperty("security.oauth2.resource.token-info-uri")
        val userInfoUri = environment
                .getProperty("security.oauth2.resource.user-info-uri")
        if (!StringUtils.hasLength(userInfoUri) && !StringUtils.hasLength(tokenInfoUri)) {
            return ConditionOutcome
                    .match(message.didNotFind("user-info-uri property").atAll())
        }
        return if (StringUtils.hasLength(tokenInfoUri) && preferTokenInfo) {
            ConditionOutcome
                    .match(message.foundExactly("preferred token-info-uri property"))
        } else ConditionOutcome.noMatch(message.didNotFind("token info").atAll())
    }

}