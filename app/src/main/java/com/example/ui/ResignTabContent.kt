package com.example.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Draw
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.AospKeyProfile
import com.example.model.SelectedApkItem
import com.example.model.SignedApkResult
import com.example.model.SigningOptions
import com.example.model.SigningUiState
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.LocalSemanticColors

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ResignControlsColumn(
    selectedApks: List<SelectedApkItem>,
    selectedAospProfile: AospKeyProfile,
    signingOptions: SigningOptions,
    signingState: SigningUiState,
    strings: UiStrings,
    onOpenFilePicker: () -> Unit,
    onRemoveApk: (String) -> Unit,
    onClearApks: () -> Unit,
    onSelectAospProfile: (AospKeyProfile) -> Unit,
    onUpdateOptions: (SigningOptions) -> Unit,
    onSignWithAospClick: () -> Unit,
    onSignWithCustomClick: () -> Unit,
    onKeyUpdaterClick: () -> Unit
) {
    val isBusy = signingState is SigningUiState.Signing || signingState is SigningUiState.AnalyzingTarget

    // 1. Target APK Picker Card
    Surface(
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(strings.resignFieldLabel, style = MaterialTheme.typography.titleSmall)
                if (selectedApks.isNotEmpty()) {
                    TextButton(
                        onClick = onClearApks,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                        modifier = Modifier.testTag("resign_clear_selection_button")
                    ) {
                        Text(strings.clearSelection, style = MaterialTheme.typography.labelMedium)
                    }
                }
            }

            Surface(
                shape = MaterialTheme.shapes.medium,
                color = MaterialTheme.colorScheme.surfaceVariant,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                modifier = Modifier
                    .fillMaxWidth()
                    .minimumInteractiveComponentSize()
                    .clickable(enabled = !isBusy, onClick = onOpenFilePicker)
                    .testTag("resign_apk_picker_field")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Filled.FolderOpen,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = if (selectedApks.isEmpty()) {
                            strings.apkFieldPlaceholder
                        } else {
                            strings.apkSelectedCount(selectedApks.size)
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (selectedApks.isEmpty()) {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        } else {
                            MaterialTheme.colorScheme.onSurface
                        },
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            if (selectedApks.isNotEmpty()) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    selectedApks.forEach { apk ->
                        InputChip(
                            selected = true,
                            onClick = { if (!isBusy) onRemoveApk(apk.id) },
                            label = {
                                Text(
                                    text = apk.displayName,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    style = MaterialTheme.typography.labelMedium
                                )
                            },
                            trailingIcon = {
                                Icon(
                                    imageVector = Icons.Filled.Close,
                                    contentDescription = strings.clearSelection,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        )
                    }
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            // 2. Signing Options & Output Configuration
            Text(strings.resignOptionsTitle, style = MaterialTheme.typography.labelLarge)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                FilterChip(
                    selected = signingOptions.signV1,
                    onClick = { onUpdateOptions(signingOptions.copy(signV1 = !signingOptions.signV1)) },
                    label = { Text("V1") },
                    modifier = Modifier.testTag("opt_v1_chip")
                )
                FilterChip(
                    selected = signingOptions.signV2,
                    onClick = { onUpdateOptions(signingOptions.copy(signV2 = !signingOptions.signV2)) },
                    label = { Text("V2") },
                    modifier = Modifier.testTag("opt_v2_chip")
                )
                FilterChip(
                    selected = signingOptions.signV3,
                    onClick = { onUpdateOptions(signingOptions.copy(signV3 = !signingOptions.signV3)) },
                    label = { Text("V3") },
                    modifier = Modifier.testTag("opt_v3_chip")
                )
                FilterChip(
                    selected = signingOptions.signV4,
                    onClick = { onUpdateOptions(signingOptions.copy(signV4 = !signingOptions.signV4)) },
                    label = { Text("V4 (.idsig)") },
                    modifier = Modifier.testTag("opt_v4_chip")
                )
                FilterChip(
                    selected = signingOptions.zipAlign4,
                    onClick = { onUpdateOptions(signingOptions.copy(zipAlign4 = !signingOptions.zipAlign4)) },
                    label = { Text(strings.zipAlignLabel) },
                    modifier = Modifier.testTag("opt_zipalign_chip")
                )
            }
            Text(
                text = strings.resignOutputHint,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            // 3. AOSP Key Profile Picker + Sign with AOSP key button
            Text(strings.aospProfileLabel, style = MaterialTheme.typography.labelLarge)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                AospKeyProfile.entries.forEach { profile ->
                    FilterChip(
                        selected = selectedAospProfile == profile,
                        onClick = { onSelectAospProfile(profile) },
                        label = {
                            Text(
                                text = profile.displayName.removePrefix("AOSP "),
                                maxLines = 1,
                                softWrap = false
                            )
                        },
                        modifier = Modifier.testTag("aosp_profile_${profile.name.lowercase()}")
                    )
                }
            }

            Button(
                onClick = onSignWithAospClick,
                enabled = selectedApks.isNotEmpty() && !isBusy,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
                    .testTag("sign_aosp_button")
            ) {
                Icon(Icons.Filled.Draw, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    text = strings.btnSignAosp,
                    style = MaterialTheme.typography.labelLarge,
                    maxLines = 1,
                    softWrap = false
                )
            }

            // 4. SIGN with custom key & Key updater buttons
            FilledTonalButton(
                onClick = onSignWithCustomClick,
                enabled = !isBusy,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
                    .testTag("sign_custom_button")
            ) {
                Icon(Icons.Filled.VpnKey, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    text = strings.btnSignCustom,
                    style = MaterialTheme.typography.labelLarge,
                    maxLines = 1,
                    softWrap = false
                )
            }

            OutlinedButton(
                onClick = onKeyUpdaterClick,
                enabled = selectedApks.isNotEmpty() && !isBusy,
                shape = MaterialTheme.shapes.medium,
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.tertiary
                ),
                border = BorderStroke(
                    1.dp,
                    if (selectedApks.isNotEmpty() && !isBusy) {
                        MaterialTheme.colorScheme.tertiary
                    } else {
                        MaterialTheme.colorScheme.outlineVariant
                    }
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
                    .testTag("key_updater_button")
            ) {
                Icon(Icons.Filled.AutoFixHigh, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    text = strings.btnKeyUpdater,
                    style = MaterialTheme.typography.labelLarge,
                    maxLines = 1,
                    softWrap = false
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ResignResultsArea(
    signingState: SigningUiState,
    strings: UiStrings,
    onInspectReport: (SignedApkResult) -> Unit,
    onSaveSignedApkAs: (SignedApkResult) -> Unit
) {
    val semantic = LocalSemanticColors.current

    when (signingState) {
        is SigningUiState.Idle -> {
            Surface(
                shape = MaterialTheme.shapes.large,
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(28.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f),
                        modifier = Modifier.size(40.dp)
                    )
                    Text(strings.resignEmptyTitle, style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = strings.resignEmptyBody,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        is SigningUiState.AnalyzingTarget -> {
            Surface(
                shape = MaterialTheme.shapes.large,
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    CircularProgressIndicator()
                    Text(
                        text = strings.analyzingTargetProgress(signingState.fileName),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }

        is SigningUiState.Signing -> {
            Surface(
                shape = MaterialTheme.shapes.large,
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    CircularProgressIndicator()
                    Text(
                        text = strings.signingProgress(
                            signingState.currentIndex,
                            signingState.totalCount,
                            signingState.currentFileName
                        ),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }

        is SigningUiState.Error -> {
            Surface(
                shape = MaterialTheme.shapes.large,
                color = MaterialTheme.colorScheme.errorContainer,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = strings.errorTitle,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                    Text(
                        text = signingState.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }

        is SigningUiState.Success -> {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                signingState.results.forEachIndexed { idx, res ->
                    Surface(
                        shape = MaterialTheme.shapes.large,
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("signed_result_card_$idx")
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Surface(
                                    shape = MaterialTheme.shapes.small,
                                    color = semantic.verifiedContainer
                                ) {
                                    Row(
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(
                                            Icons.Filled.CheckCircle,
                                            contentDescription = null,
                                            tint = semantic.verified,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(Modifier.width(6.dp))
                                        Text(
                                            text = strings.resignSuccessTitle,
                                            style = MaterialTheme.typography.labelMedium,
                                            fontWeight = FontWeight.Bold,
                                            color = semantic.verified
                                        )
                                    }
                                }
                                Text(
                                    text = formatByteSize(res.outputSizeBytes),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }

                            Text(
                                text = res.verificationReport.appLabel,
                                style = MaterialTheme.typography.titleMedium
                            )

                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                res.appliedSchemes.forEach { scheme ->
                                    Surface(
                                        shape = MaterialTheme.shapes.extraSmall,
                                        color = semantic.verifiedContainer
                                    ) {
                                        Text(
                                            text = scheme.label,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = semantic.verified,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                        )
                                    }
                                }
                                if (res.isZipAligned4) {
                                    Surface(
                                        shape = MaterialTheme.shapes.extraSmall,
                                        color = MaterialTheme.colorScheme.primaryContainer
                                    ) {
                                        Text(
                                            text = "ZipAligned 4B",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                        )
                                    }
                                }
                            }

                            Text(
                                text = res.outputPath,
                                fontFamily = JetBrainsMonoFontFamily,
                                fontSize = 11.5.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${res.signerName} • SHA-256: ${res.certSha256.take(24)}…",
                                fontFamily = JetBrainsMonoFontFamily,
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            res.v4IdsigPath?.let { idsig ->
                                Text(
                                    text = "V4: $idsig",
                                    fontFamily = JetBrainsMonoFontFamily,
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = { onInspectReport(res) },
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                                    modifier = Modifier
                                        .weight(1f)
                                        .minimumInteractiveComponentSize()
                                        .testTag("inspect_signed_report_$idx")
                                ) {
                                    Icon(Icons.Filled.VerifiedUser, null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text(
                                        text = strings.viewFullReport,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        softWrap = false
                                    )
                                }
                                OutlinedButton(
                                    onClick = { onSaveSignedApkAs(res) },
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                                    modifier = Modifier
                                        .weight(1f)
                                        .minimumInteractiveComponentSize()
                                        .testTag("save_signed_apk_as_$idx")
                                ) {
                                    Icon(Icons.Filled.SaveAlt, null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text(
                                        text = strings.saveSignedApkAs,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        softWrap = false
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
