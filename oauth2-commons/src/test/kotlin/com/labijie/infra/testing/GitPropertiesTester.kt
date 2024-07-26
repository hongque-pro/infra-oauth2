/**
 * @author Anders Xiao
 * @date 2024-07-26
 */
package com.labijie.infra.testing

import com.labijie.infra.oauth2.OAuth2Utils
import kotlin.test.Test
import kotlin.test.assertEquals


class GitPropertiesTester {

    @Test
    fun testGetGitProperties() {
        val properties = OAuth2Utils.getInfraOAuth2GitProperties()

        assertEquals("oauth2-commons", properties.getProperty("project.name"))
    }
}