package com.github.snuxoll.intellij.azuredbauth.database

enum class AuthType(val displayName: String, val enabled: Boolean = true) {
    DEFAULT("Default Authentication"),
    AZURE_CLI("Azure CLI"),
    MANAGED_IDENTITY("Managed Identity", false),
    SERVICE_PRINCIPAL("Service Principal", false);
}