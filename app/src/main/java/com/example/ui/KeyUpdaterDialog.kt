package com.example.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.crypto.X509DerBuilder
import com.example.model.ClonedKeySpec
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.LocalSemanticColors

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun KeyUpdaterDialog(
    spec: ClonedKeySpec,
    strings: UiStrings,
    onUpdateSpec: (ClonedKeySpec) -> Unit,
    onDismiss: () -> Unit,
    onSaveKeyOnly: (ClonedKeySpec) -> Unit,
    onGenerateAndResign: (ClonedKeySpec) -> Unit
) {
    val semantic = LocalSemanticColors.current

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 6.dp,
            modifier = Modifier
                .fillMaxWidth(0.95f)
                .heightIn(max = 780.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.AutoFixHigh,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.tertiary
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = strings.keyUpdaterTitle,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    TextButton(onClick = onDismiss) {
                        Text(strings.close)
                    }
                }

                Text(
                    text = strings.keyUpdaterSubtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(Modifier.height(10.dp))

                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // Verified Source Certificate Summary Card
                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = semantic.verifiedContainer,
                        border = BorderStroke(1.dp, semantic.verified.copy(alpha = 0.4f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    Icons.Filled.VerifiedUser,
                                    contentDescription = null,
                                    tint = semantic.verified,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    text = "${strings.sourceKeyVerifiedBadge} • ${spec.sourceAppLabel}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = semantic.verified
                                )
                            }
                            Text(
                                text = spec.sourceCert.subjectDn,
                                fontFamily = JetBrainsMonoFontFamily,
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "SHA-256: ${spec.sourceCert.sha256}",
                                fontFamily = JetBrainsMonoFontFamily,
                                fontSize = 10.5.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    // Preserved Cryptographic Structure Card
                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = strings.preservedStructureLabel,
                                style = MaterialTheme.typography.labelLarge
                            )
                            ComparisonLine(
                                label = "Keypair / SigAlg",
                                value = "${spec.keyAlgorithm} ${spec.keySizeBits} bits • ${spec.sigAlgName} • X.509 v${spec.x509Version}"
                            )
                            ComparisonLine(
                                label = "RDN Order",
                                value = spec.orderedRdnSlots.joinToString(" → ") { it.key }.ifEmpty { "CN" }
                            )
                            ComparisonLine(
                                label = "X.509 Extensions",
                                value = buildList {
                                    if (spec.sourceCert.keyUsage.isNotEmpty()) {
                                        add("KeyUsage(${spec.sourceCert.keyUsage.joinToString(",")})")
                                    }
                                    if (spec.extendedKeyUsageOids.isNotEmpty()) {
                                        add("EKU(${spec.extendedKeyUsageOids.size})")
                                    }
                                    spec.sourceCert.basicConstraints?.let { add(it) }
                                    if (spec.includeSki) add("SKI(New)")
                                    if (spec.includeAki) add("AKI(New)")
                                }.joinToString(" • ").ifEmpty { "Standard v3" }
                            )
                            ComparisonLine(
                                label = "Target Span",
                                value = "${spec.validityDays} days"
                            )
                        }
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                    // Editable Renewed Identity
                    Text(strings.renewedIdentityLabel, style = MaterialTheme.typography.labelLarge)

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = spec.newAlias,
                            onValueChange = { onUpdateSpec(spec.copy(newAlias = it)) },
                            label = { Text(strings.aliasLabel) },
                            singleLine = true,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("key_updater_alias_input")
                        )
                        OutlinedTextField(
                            value = spec.newPassword,
                            onValueChange = { onUpdateSpec(spec.copy(newPassword = it)) },
                            label = { Text(strings.passwordLabel) },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.weight(1f)
                        )
                    }

                    OutlinedTextField(
                        value = spec.newCommonName,
                        onValueChange = { onUpdateSpec(spec.copy(newCommonName = it)) },
                        label = { Text("CN (Common Name)") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("key_updater_cn_input")
                    )

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = spec.newOrgUnit,
                            onValueChange = { onUpdateSpec(spec.copy(newOrgUnit = it)) },
                            label = { Text("OU") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = spec.newOrganization,
                            onValueChange = { onUpdateSpec(spec.copy(newOrganization = it)) },
                            label = { Text("O") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = spec.newLocality,
                            onValueChange = { onUpdateSpec(spec.copy(newLocality = it)) },
                            label = { Text("L") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = spec.newState,
                            onValueChange = { onUpdateSpec(spec.copy(newState = it)) },
                            label = { Text("ST") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = spec.newCountry,
                            onValueChange = { onUpdateSpec(spec.copy(newCountry = it.take(2))) },
                            label = { Text("C") },
                            singleLine = true,
                            modifier = Modifier.weight(0.7f)
                        )
                    }

                    OutlinedTextField(
                        value = spec.newEmail,
                        onValueChange = { onUpdateSpec(spec.copy(newEmail = it)) },
                        label = { Text("Email (E)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = spec.newValidityDays.toString(),
                            onValueChange = { raw ->
                                val digits = raw.filter { it.isDigit() }
                                val days = digits.toLongOrNull()?.coerceAtLeast(1L) ?: 365L
                                onUpdateSpec(spec.copy(newValidityDays = days))
                            },
                            label = { Text(strings.validityDaysLabel) },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier.weight(0.9f)
                        )
                        OutlinedTextField(
                            value = spec.newSerialNumberHex,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text(strings.serialHexLabel) },
                            singleLine = true,
                            trailingIcon = {
                                TextButton(
                                    onClick = {
                                        val s = X509DerBuilder.generateRandomPositiveSerial()
                                        onUpdateSpec(
                                            spec.copy(
                                                newSerialNumberDecimal = s.toString(),
                                                newSerialNumberHex = "0x" + s.toString(16)
                                            )
                                        )
                                    }
                                ) {
                                    Text("New")
                                }
                            },
                            modifier = Modifier.weight(1.3f)
                        )
                    }

                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(
                            selected = spec.signV1,
                            onClick = { onUpdateSpec(spec.copy(signV1 = !spec.signV1)) },
                            label = { Text("V1") }
                        )
                        FilterChip(
                            selected = spec.signV2,
                            onClick = { onUpdateSpec(spec.copy(signV2 = !spec.signV2)) },
                            label = { Text("V2") }
                        )
                        FilterChip(
                            selected = spec.signV3,
                            onClick = { onUpdateSpec(spec.copy(signV3 = !spec.signV3)) },
                            label = { Text("V3") }
                        )
                        FilterChip(
                            selected = spec.signV4,
                            onClick = { onUpdateSpec(spec.copy(signV4 = !spec.signV4)) },
                            label = { Text("V4") }
                        )
                    }
                }

                Spacer(Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { onSaveKeyOnly(spec) },
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                        modifier = Modifier
                            .weight(0.9f)
                            .minimumInteractiveComponentSize()
                            .testTag("key_updater_save_only_button")
                    ) {
                        Icon(Icons.Filled.SaveAlt, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(strings.saveClonedKeyOnly, maxLines = 1, overflow = TextOverflow.Ellipsis, softWrap = false)
                    }
                    Button(
                        onClick = { onGenerateAndResign(spec) },
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                        modifier = Modifier
                            .weight(1.2f)
                            .minimumInteractiveComponentSize()
                            .testTag("key_updater_generate_resign_button")
                    ) {
                        Icon(Icons.Filled.AutoFixHigh, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(strings.generateAndResignButton, maxLines = 1, overflow = TextOverflow.Ellipsis, softWrap = false)
                    }
                }
            }
        }
    }
}

@Composable
private fun ComparisonLine(label: String, value: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            fontFamily = JetBrainsMonoFontFamily,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}
