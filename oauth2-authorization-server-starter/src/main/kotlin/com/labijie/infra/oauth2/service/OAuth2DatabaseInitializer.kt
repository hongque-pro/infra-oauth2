package com.labijie.infra.oauth2.service

import org.springframework.boot.jdbc.init.DataSourceScriptDatabaseInitializer
import org.springframework.boot.sql.init.DatabaseInitializationSettings
import javax.sql.DataSource

object OAuth2DatabaseInitializationSettings : DatabaseInitializationSettings() {
    init {
        schemaLocations = listOf("classpath:org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
    }
}

/**
 * @author Anders Xiao
 * @date 2023-11-27
 */
class OAuth2DatabaseInitializer(dataSource: DataSource) : DataSourceScriptDatabaseInitializer(dataSource, OAuth2DatabaseInitializationSettings) {
}