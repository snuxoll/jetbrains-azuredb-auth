package com.snuxoll.azuredbauth.database

import com.azure.core.credential.TokenCredential
import com.azure.core.credential.TokenRequestContext
import com.azure.identity.*
import com.snuxoll.azuredbauth.Messages
import com.snuxoll.azuredbauth.database.widget.AzureAuthWidget
import com.intellij.credentialStore.Credentials
import com.intellij.database.Dbms
import com.intellij.database.access.DatabaseCredentials
import com.intellij.database.dataSource.*
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.project.Project
import kotlinx.coroutines.reactor.awaitSingle

private const val CREDENTIAL_PROVIDER_ID = "com.github.snuxoll.intellij.azuredbauth.database"

@Suppress("UnstableApiUsage")
class AzureAuthProvider : DatabaseAuthProvider {

    private val credentials: MutableMap<String, TokenCredential> = mutableMapOf()

    override fun getDisplayName(): String {
        return Messages.displayName
    }

    override fun getId(): String = CREDENTIAL_PROVIDER_ID

    override suspend fun interceptConnection(
        proto: DatabaseConnectionInterceptor.ProtoConnection,
        silent: Boolean
    ): Boolean {
        val authType = proto.connectionPoint.getAdditionalProperty(AZURE_AUTH_TYPE_KEY)
            ?.let { AuthType.valueOf(it) }
        if (authType == null) {
            LOG.error("No auth type given for connection ${proto.connectionPoint.dataSource.uniqueId}, but Azure Auth was requested")
            return super.interceptConnection(proto, silent)
        }
        val username = proto.credentials.getCredentials(proto.connectionPoint).userName
        val credentials = getCredentials(proto.connectionPoint.dataSource, authType)
        val token = credentials.getToken(tokenRequestContext).awaitSingle()

        DatabaseCredentialsAuthProvider.applyCredentials(proto, Credentials(username, token.token), true)

        return true
    }

    fun clearCredentials(connectionPoint: DatabaseConnectionPoint) {
        credentials.remove(connectionPoint.dataSource.uniqueId)
    }

    private fun getCredentials(
        connectionPoint: DatabaseConnectionPoint,
        authType: AuthType
    ): TokenCredential {
        return when (authType) {
            AuthType.DEFAULT -> getDefaultAzureCredentials(connectionPoint)
            AuthType.AZURE_CLI -> getAzureCLICredentials(connectionPoint)
            AuthType.INTERACTIVE -> getInteractiveCredentials(connectionPoint)
            AuthType.MANAGED_IDENTITY -> getManagedIdentityCredentials(connectionPoint)
            AuthType.SERVICE_PRINCIPAL -> getServicePrincipalCredentials(connectionPoint)
        }
    }

    private fun getInteractiveCredentials(connectionPoint: DatabaseConnectionPoint): InteractiveBrowserCredential {
        val connectionId = connectionPoint.dataSource.uniqueId
        return credentials[connectionId] as? InteractiveBrowserCredential
            ?: InteractiveBrowserCredentialBuilder().build().also {
                credentials[connectionId] = it
            }
    }

    private fun getAzureCLICredentials(connectionPoint: DatabaseConnectionPoint): AzureCliCredential {
        val connectionId = connectionPoint.dataSource.uniqueId
        return credentials[connectionId] as? AzureCliCredential
            ?: AzureCliCredentialBuilder().build().also {
                credentials[connectionId] = it
            }
    }

    private fun getManagedIdentityCredentials(connectionPoint: DatabaseConnectionPoint): ManagedIdentityCredential {
        val connectionId = connectionPoint.dataSource.uniqueId
        return credentials[connectionId] as? ManagedIdentityCredential
            ?: ManagedIdentityCredentialBuilder().build().also {
                credentials[connectionId] = it
            }
    }

    private fun getServicePrincipalCredentials(connectionPoint: DatabaseConnectionPoint): UsernamePasswordCredential {
        val connectionId = connectionPoint.dataSource.uniqueId
        return credentials[connectionId] as? UsernamePasswordCredential
            ?: UsernamePasswordCredentialBuilder().build().also {
                credentials[connectionId] = it
            }
    }

    private fun getDefaultAzureCredentials(connectionPoint: DatabaseConnectionPoint): DefaultAzureCredential {
        val connectionId = connectionPoint.dataSource.uniqueId
        return credentials[connectionId] as? DefaultAzureCredential
            ?: DefaultAzureCredentialBuilder().build().also {
                credentials[connectionId] = it
            }
    }

    override fun createWidget(
        project: Project?,
        credentials: DatabaseCredentials,
        config: DatabaseConnectionConfig
    ): DatabaseAuthProvider.AuthWidget = AzureAuthWidget(project, credentials, config)

    override fun getApplicability(
        point: DatabaseConnectionPoint,
        level: DatabaseAuthProvider.ApplicabilityLevel
    ): DatabaseAuthProvider.ApplicabilityLevel.Result =
        when (point.dbms) {
            Dbms.POSTGRES -> DatabaseAuthProvider.ApplicabilityLevel.Result.APPLICABLE
            Dbms.MYSQL -> DatabaseAuthProvider.ApplicabilityLevel.Result.APPLICABLE
            else -> DatabaseAuthProvider.ApplicabilityLevel.Result.NOT_APPLICABLE
        }


    companion object {
        private val LOG = logger<AzureAuthProvider>()
    }
}

private val tokenRequestContext =
    TokenRequestContext().setScopes(listOf("https://ossrdbms-aad.database.windows.net/.default"))