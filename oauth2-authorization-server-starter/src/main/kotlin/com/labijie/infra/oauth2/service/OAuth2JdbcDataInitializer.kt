package com.labijie.infra.oauth2.service

import com.labijie.infra.oauth2.OAuth2ServerUtils
import com.labijie.infra.oauth2.configuration.OAuth2ServerProperties
import com.labijie.infra.utils.logger
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ResourceLoaderAware
import org.springframework.core.io.ResourceLoader
import org.springframework.jdbc.datasource.init.DatabasePopulatorUtils
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator
import org.springframework.jdbc.datasource.init.ScriptException
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import javax.sql.DataSource

/**
 * @author Anders Xiao
 * @date 2023-11-27
 */
class OAuth2JdbcDataInitializer(
    private val dataSource: DataSource,
    private val serverProperties: OAuth2ServerProperties
) :
    ResourceLoaderAware,
    ApplicationRunner,
    ApplicationContextAware {

    private val logger: Logger by lazy {
        LoggerFactory.getLogger(OAuth2JdbcDataInitializer::class.java)
    }
    private lateinit var resourceLoader: ResourceLoader
    private lateinit var applicationContext: ApplicationContext

    override fun run(args: ApplicationArguments?) {
        val clientRepository = applicationContext.getBeanProvider(JdbcRegisteredClientRepository::class.java).ifAvailable
        val oauth2AuthorizationService = applicationContext.getBeanProvider(JdbcOAuth2AuthorizationService::class.java).ifAvailable
        val consentService = applicationContext.getBeanProvider(JdbcOAuth2AuthorizationConsentService::class.java).ifAvailable
        var scripts = 0;

        try {
            val populator = ResourceDatabasePopulator()

            consentService?.let {
                populator.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
                scripts++
            }
            clientRepository?.let {
                populator.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
                scripts++
            }
            oauth2AuthorizationService?.let {
                populator.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
                scripts++
            }
            if(scripts > 0) {

                populator.setContinueOnError(false)
                populator.setSqlScriptEncoding("UTF-8")

                DatabasePopulatorUtils.execute(populator, this.dataSource)

                if (serverProperties.defaultClient.enabled) {
                    clientRepository?.let {
                        clientRepository.saveDefaultClientRegistrationIfNotExisted(serverProperties)
                    }
                }
            }

        } catch (_: ScriptException) {
            //logger.warn("Execute oauth2 schema initialization sql failed.")
        }
        catch (e: Throwable) {
            logger.error(e.toString())
        }
    }

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }

    private fun RegisteredClientRepository.saveDefaultClientRegistrationIfNotExisted(
        properties: OAuth2ServerProperties
    ) {
        if (properties.defaultClient.enabled) {
            val passwordRegisteredClient = OAuth2ServerUtils.createDefaultClientRegistration(properties)
            val registeredClients = mutableListOf<RegisteredClient>()
            registeredClients.add(passwordRegisteredClient)

            registeredClients.forEach { registeredClient: RegisteredClient ->
                val id = registeredClient.id
                val clientId = registeredClient.clientId
                val dbRegisteredClient = this.findById(id) ?: this.findByClientId(clientId)
                if (dbRegisteredClient == null) {
                    this.save(registeredClient)

                    logger.info("Default client with client id '${properties.defaultClient.clientId}', secret '${properties.defaultClient.secret}' has been created.")
                }
            }

        }
    }

    override fun setResourceLoader(resourceLoader: ResourceLoader) {
        this.resourceLoader = resourceLoader
    }

    private fun ResourceDatabasePopulator.addScript(scriptPath: String): ResourceDatabasePopulator {
        this.addScript(resourceLoader.getResource(scriptPath))
        return this
    }
}