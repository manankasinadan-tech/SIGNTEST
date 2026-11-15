package com.example.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.crypto.GsiPartitionReSigner
import com.example.model.AospKeyProfile
import com.example.model.GroupKeyAssignment
import com.example.model.PartitionAuditReport
import com.example.model.PartitionKeyStrategyMode
import com.example.model.PartitionResignPlan
import com.example.model.StoredKeyEntry
import com.example.ui.theme.LocalSemanticColors

@Composable
fun VerifyBeforeResignDialog(
    strings: UiStrings,
    onDismiss: () -> Unit,
    onVerifyNow: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = {
            Icon(
                imageVector = Icons.Filled.VerifiedUser,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
        },
        title = {
            Text(text = strings.verifyFirstPopupTitle)
        },
        text = {
            Text(text = strings.verifyFirstPopupBody)
        },
        confirmButton = {
            Button(
                onClick = onVerifyNow,
                modifier = Modifier.testTag("verify_before_resign_confirm")
            ) {
                Text(strings.verifyFirstActionButton)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(strings.cancel)
            }
        }
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun GsiResignStrategyDialog(
    auditReport: PartitionAuditReport,
    vaultKeys: List<StoredKeyEntry>,
    strings: UiStrings,
    onDismiss: () -> Unit,
    onConfirmPlan: (PartitionResignPlan) -> Unit
) {
    BackHandler(onBack = onDismiss)
    val semantic = LocalSemanticColors.current

    var strategyMode by remember { mutableStateOf(PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP) }
    var saveClonedToVault by remember { mutableStateOf(true) }
    var zipAlign4 by remember { mutableStateOf(true) }

    var assignments by remember(auditReport.rootPath, vaultKeys.size) {
        mutableStateOf(
            auditReport.signatureGroups.map { grp ->
                GroupKeyAssignment(
                    groupId = grp.groupId,
                    groupDisplayName = grp.displayName,
                    inferredRole = grp.inferredRole,
                    apkCount = grp.apks.size,
                    aospProfile = GsiPartitionReSigner.defaultProfileForRole(grp.inferredRole),
                    customKeyEntry = vaultKeys.firstOrNull(),
                    customKeyPassword = vaultKeys.firstOrNull()?.defaultPasswordHint ?: "signerlab"
                )
            }
        )
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.94f)
                .fillMaxHeight(0.88f)
                .testTag("gsi_resign_strategy_dialog"),
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 6.dp,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                // Header
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 20.dp, end = 8.dp, top = 14.dp, bottom = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Filled.AutoFixHigh,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = strings.gsiStrategyTitle,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Filled.Close, contentDescription = strings.cancel)
                    }
                }

                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 18.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = strings.gsiStrategySubtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = semantic.warningContainer,
                        border = BorderStroke(1.dp, semantic.warning.copy(alpha = 0.4f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Warning,
                                contentDescription = null,
                                tint = semantic.warning,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = strings.directReplaceWarning,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }

                    // Strategy options
                    StrategyOptionCard(
                        selected = strategyMode == PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP,
                        title = strings.strategyAutoCloneTitle,
                        description = strings.strategyAutoCloneDesc,
                        onClick = { strategyMode = PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP },
                        testTag = "strategy_auto_clone"
                    )
                    StrategyOptionCard(
                        selected = strategyMode == PartitionKeyStrategyMode.AOSP_BY_ROLE,
                        title = strings.strategyAospTitle,
                        description = strings.strategyAospDesc,
                        onClick = { strategyMode = PartitionKeyStrategyMode.AOSP_BY_ROLE },
                        testTag = "strategy_aosp"
                    )
                    StrategyOptionCard(
                        selected = strategyMode == PartitionKeyStrategyMode.CUSTOM_VAULT,
                        title = strings.strategyCustomTitle,
                        description = strings.strategyCustomDesc,
                        onClick = { strategyMode = PartitionKeyStrategyMode.CUSTOM_VAULT },
                        testTag = "strategy_custom"
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(strings.zipAlignLabel, style = MaterialTheme.typography.bodyMedium)
                        Switch(checked = zipAlign4, onCheckedChange = { zipAlign4 = it })
                    }

                    if (strategyMode == PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = strings.saveClonedToVaultToggle,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.weight(1f)
                            )
                            Switch(checked = saveClonedToVault, onCheckedChange = { saveClonedToVault = it })
                        }
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                    Text(
                        text = strings.perGroupMappingTitle,
                        style = MaterialTheme.typography.titleSmall
                    )

                    assignments.forEachIndexed { idx, assign ->
                        Surface(
                            shape = MaterialTheme.shapes.medium,
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(
                                    text = "${assign.groupDisplayName} (${strings.groupApkCount(assign.apkCount)})",
                                    style = MaterialTheme.typography.labelLarge
                                )
                                when (strategyMode) {
                                    PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP -> {
                                        Text(
                                            text = "→ Key updater GSI (${assign.inferredRole})",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                    }

                                    PartitionKeyStrategyMode.AOSP_BY_ROLE -> {
                                        FlowRow(
                                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                                            verticalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            AospKeyProfile.entries.forEach { profile ->
                                                FilterChip(
                                                    selected = assign.aospProfile == profile,
                                                    onClick = {
                                                        val mutable = assignments.toMutableList()
                                                        mutable[idx] = assign.copy(aospProfile = profile)
                                                        assignments = mutable
                                                    },
                                                    label = {
                                                        Text(
                                                            text = profile.displayName.removePrefix("AOSP "),
                                                            style = MaterialTheme.typography.labelSmall
                                                        )
                                                    },
                                                    leadingIcon = {
                                                        Icon(Icons.Filled.Shield, null, modifier = Modifier.size(14.dp))
                                                    }
                                                )
                                            }
                                        }
                                    }

                                    PartitionKeyStrategyMode.CUSTOM_VAULT -> {
                                        if (vaultKeys.isEmpty()) {
                                            Text(
                                                text = strings.emptyVault,
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.error
                                            )
                                        } else {
                                            FlowRow(
                                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                                verticalArrangement = Arrangement.spacedBy(4.dp)
                                            ) {
                                                vaultKeys.forEach { key ->
                                                    FilterChip(
                                                        selected = assign.customKeyEntry?.id == key.id,
                                                        onClick = {
                                                            val mutable = assignments.toMutableList()
                                                            mutable[idx] = assign.copy(
                                                                customKeyEntry = key,
                                                                customKeyPassword = key.defaultPasswordHint ?: "signerlab"
                                                            )
                                                            assignments = mutable
                                                        },
                                                        label = {
                                                            Text(key.alias, style = MaterialTheme.typography.labelSmall)
                                                        },
                                                        leadingIcon = {
                                                            Icon(Icons.Filled.Key, null, modifier = Modifier.size(14.dp))
                                                        }
                                                    )
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(onClick = onDismiss) {
                        Text(strings.cancel)
                    }
                    Spacer(Modifier.width(8.dp))
                    Button(
                        onClick = {
                            onConfirmPlan(
                                PartitionResignPlan(
                                    strategyMode = strategyMode,
                                    groupAssignments = assignments,
                                    zipAlign4 = zipAlign4,
                                    saveClonedKeysToVault = saveClonedToVault
                                )
                            )
                        },
                        enabled = strategyMode != PartitionKeyStrategyMode.CUSTOM_VAULT || vaultKeys.isNotEmpty(),
                        modifier = Modifier.testTag("confirm_gsi_resign_button")
                    ) {
                        Text(strings.gsiStartResignButton)
                    }
                }
            }
        }
    }
}

@Composable
private fun StrategyOptionCard(
    selected: Boolean,
    title: String,
    description: String,
    onClick: () -> Unit,
    testTag: String
) {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = if (selected) {
            MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        border = BorderStroke(
            width = if (selected) 1.5.dp else 1.dp,
            color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
        ),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(testTag)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            RadioButton(selected = selected, onClick = onClick)
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
