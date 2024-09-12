package com.github.snuxoll.intellij.azuredbauth.settings

import com.github.snuxoll.intellij.azuredbauth.Messages
import com.github.snuxoll.intellij.azuredbauth.database.AuthType
import com.github.snuxoll.intellij.azuredbauth.ui.AuthTypeComboRenderer
import com.intellij.openapi.options.BoundSearchableConfigurable
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogPanel
import com.intellij.ui.dsl.builder.bindItem
import com.intellij.ui.dsl.builder.panel
import com.intellij.ui.dsl.builder.toNullableProperty

class AzureAuthConfigurable(private val project: Project) : BoundSearchableConfigurable(
    Messages.displayName,
    "settings.azuredbauth",
    "com.github.snuxoll.intellij.azuredbauth.settings.AzureDbAuthSettings"
) {

    private val settings get() = AzureAuthSettings.getInstance(project)

    override fun createPanel(): DialogPanel {
        return panel {
            indent {
                row(Messages.defaultAuthModeLabel) {
                    comboBox(AuthType.entries)
                        .bindItem(settings::authType.toNullableProperty())
                        .applyToComponent {
                            setRenderer(AuthTypeComboRenderer)
                        }
                }
            }
        }
    }

    override fun apply() {
        super.apply()
    }
}
