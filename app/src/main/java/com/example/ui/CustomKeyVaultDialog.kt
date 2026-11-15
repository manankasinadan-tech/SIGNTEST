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
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.model.CustomKeyCreationSpec
import com.example.model.KeyAlgorithmOption
import com.example.model.StoredKeyEntry
import com.example.ui.theme.JetBrainsMonoFontFamily

@OptIn(ExperimentalLayoutApi::class, androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun CustomKeyVaultDialog(
    vaultKeys: List<StoredKeyEntry>,
    hasTargetApks: Boolean,
    strings: UiStrings,
    onDismiss: () -> Unit,
    onSignWithVaultKey: (StoredKeyEntry, String) -> Unit,
    onExportVaultKey: (StoredKeyEntry) -> Unit,
    onDeleteVaultKey: (String) -> Unit,
    onCreateCustomKey: (CustomKeyCreationSpec) -> Unit,
    onPickImportKeystoreFile: (storePassword: String, keyPassword: String) -> Unit
) {
    var selectedSubTab by rememberSaveable { mutableIntStateOf(if (vaultKeys.isEmpty()) 1 else 0) }

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
                .heightIn(max = 760.dp)
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
                            Icons.Filled.VpnKey,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = strings.customKeyTitle,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    TextButton(onClick = onDismiss) {
                        Text(strings.close)
                    }
                }

                PrimaryTabRow(selectedTabIndex = selectedSubTab) {
                    Tab(
                        selected = selectedSubTab == 0,
                        onClick = { selectedSubTab = 0 },
                        text = { Text("${strings.vaultTab} (${vaultKeys.size})", maxLines = 1) },
                        modifier = Modifier.testTag("custom_key_vault_tab")
                    )
                    Tab(
                        selected = selectedSubTab == 1,
                        onClick = { selectedSubTab = 1 },
                        text = { Text(strings.createKeyTab, maxLines = 1) },
                        modifier = Modifier.testTag("custom_key_create_tab")
                    )
                    Tab(
                        selected = selectedSubTab == 2,
                        onClick = { selectedSubTab = 2 },
                        text = { Text(strings.importKeyTab, maxLines = 1) },
                        modifier = Modifier.testTag("custom_key_import_tab")
                    )
                }

                Spacer(Modifier.height(12.dp))

                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    when (selectedSubTab) {
                        0 -> VaultKeysTab(
                            vaultKeys = vaultKeys,
                            hasTargetApks = hasTargetApks,
                            strings = strings,
                            onSignWithVaultKey = onSignWithVaultKey,
                            onExportVaultKey = onExportVaultKey,
                            onDeleteVaultKey = onDeleteVaultKey
                        )

                        1 -> CreateCustomKeyTab(
                            hasTargetApks = hasTargetApks,
                            strings = strings,
                            onCreateCustomKey = onCreateCustomKey
                        )

                        2 -> ImportKeystoreTab(
                            strings = strings,
                            onPickImportKeystoreFile = onPickImportKeystoreFile
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun VaultKeysTab(
    vaultKeys: List<StoredKeyEntry>,
    hasTargetApks: Boolean,
    strings: UiStrings,
    onSignWithVaultKey: (StoredKeyEntry, String) -> Unit,
    onExportVaultKey: (StoredKeyEntry) -> Unit,
    onDeleteVaultKey: (String) -> Unit
) {
    if (vaultKeys.isEmpty()) {
        Surface(
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = strings.emptyVault,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp)
            )
        }
        return
    }

    vaultKeys.forEachIndexed { idx, entry ->
        var passInput by rememberSaveable(entry.id) {
            mutableStateOf(entry.defaultPasswordHint ?: "signerlab")
        }
        Surface(
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(entry.alias, style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = "${entry.keyAlgorithm} ${entry.keySizeBits} • ${entry.sigAlgName} • ${entry.origin.name}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    IconButton(
                        onClick = { onExportVaultKey(entry) },
                        modifier = Modifier.testTag("export_vault_key_$idx")
                    ) {
                        Icon(Icons.Filled.SaveAlt, contentDescription = strings.exportP12Button)
                    }
                    IconButton(
                        onClick = { onDeleteVaultKey(entry.id) },
                        modifier = Modifier.testTag("delete_vault_key_$idx")
                    ) {
                        Icon(
                            Icons.Filled.DeleteOutline,
                            contentDescription = strings.deleteKeyButton,
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                }

                Text(
                    text = entry.subjectDn,
                    fontFamily = JetBrainsMonoFontFamily,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "SHA-256: ${entry.sha256.take(32)}…",
                    fontFamily = JetBrainsMonoFontFamily,
                    fontSize = 10.5.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = passInput,
                        onValueChange = { passInput = it },
                        label = { Text(strings.passwordLabel) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.weight(1f)
                    )
                    Button(
                        onClick = { onSignWithVaultKey(entry, passInput) },
                        enabled = hasTargetApks,
                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 12.dp),
                        modifier = Modifier
                            .minimumInteractiveComponentSize()
                            .testTag("use_vault_key_$idx")
                    ) {
                        Text(strings.useThisKeyButton, maxLines = 1, softWrap = false)
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CreateCustomKeyTab(
    hasTargetApks: Boolean,
    strings: UiStrings,
    onCreateCustomKey: (CustomKeyCreationSpec) -> Unit
) {
    var alias by rememberSaveable { mutableStateOf("custom_release") }
    var password by rememberSaveable { mutableStateOf("signerlab") }
    var selectedAlg by rememberSaveable { mutableStateOf(KeyAlgorithmOption.RSA_2048) }
    var sigAlg by rememberSaveable { mutableStateOf(KeyAlgorithmOption.RSA_2048.defaultSigAlg) }
    var validityYears by rememberSaveable { mutableStateOf("25") }
    var cn by rememberSaveable { mutableStateOf("SignerLAB Release") }
    var ou by rememberSaveable { mutableStateOf("Engineering") }
    var org by rememberSaveable { mutableStateOf("SignerLAB") }
    var locality by rememberSaveable { mutableStateOf("Paris") }
    var state by rememberSaveable { mutableStateOf("IDF") }
    var country by rememberSaveable { mutableStateOf("FR") }
    var email by rememberSaveable { mutableStateOf("") }
    var saveToVault by rememberSaveable { mutableStateOf(true) }

    OutlinedTextField(
        value = alias,
        onValueChange = { alias = it },
        label = { Text(strings.aliasLabel) },
        singleLine = true,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("custom_key_alias_input")
    )
    OutlinedTextField(
        value = password,
        onValueChange = { password = it },
        label = { Text(strings.passwordLabel) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("custom_key_password_input")
    )

    Text(strings.algorithmLabel, style = MaterialTheme.typography.labelLarge)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        KeyAlgorithmOption.entries.forEach { opt ->
            FilterChip(
                selected = selectedAlg == opt,
                onClick = {
                    selectedAlg = opt
                    sigAlg = opt.defaultSigAlg
                },
                label = { Text(opt.label) }
            )
        }
    }

    Text(strings.sigAlgLabel, style = MaterialTheme.typography.labelLarge)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        selectedAlg.supportedSigAlgs.forEach { algName ->
            FilterChip(
                selected = sigAlg == algName,
                onClick = { sigAlg = algName },
                label = { Text(algName, maxLines = 1, softWrap = false) }
            )
        }
    }

    OutlinedTextField(
        value = validityYears,
        onValueChange = { validityYears = it.filter { ch -> ch.isDigit() } },
        label = { Text(strings.validityYearsLabel) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        singleLine = true,
        modifier = Modifier.fillMaxWidth()
    )

    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    Text(strings.dnFieldsLabel, style = MaterialTheme.typography.labelLarge)

    OutlinedTextField(value = cn, onValueChange = { cn = it }, label = { Text("CN (Common Name)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(value = ou, onValueChange = { ou = it }, label = { Text("OU") }, singleLine = true, modifier = Modifier.weight(1f))
        OutlinedTextField(value = org, onValueChange = { org = it }, label = { Text("O") }, singleLine = true, modifier = Modifier.weight(1f))
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(value = locality, onValueChange = { locality = it }, label = { Text("L") }, singleLine = true, modifier = Modifier.weight(1f))
        OutlinedTextField(value = state, onValueChange = { state = it }, label = { Text("ST") }, singleLine = true, modifier = Modifier.weight(1f))
        OutlinedTextField(value = country, onValueChange = { country = it.take(2) }, label = { Text("C") }, singleLine = true, modifier = Modifier.weight(0.7f))
    }
    OutlinedTextField(value = email, onValueChange = { email = it }, label = { Text("Email (E)") }, singleLine = true, modifier = Modifier.fillMaxWidth())

    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = saveToVault, onCheckedChange = { saveToVault = it })
        Text(strings.saveToVaultLabel, style = MaterialTheme.typography.bodyMedium)
    }

    Button(
        onClick = {
            onCreateCustomKey(
                CustomKeyCreationSpec(
                    alias = alias,
                    password = password,
                    algorithm = selectedAlg,
                    sigAlgorithm = sigAlg,
                    validityYears = validityYears.toIntOrNull()?.coerceIn(1, 100) ?: 25,
                    commonName = cn,
                    orgUnit = ou,
                    organization = org,
                    locality = locality,
                    state = state,
                    country = country,
                    email = email,
                    saveToVault = saveToVault
                )
            )
        },
        enabled = cn.isNotBlank() && (hasTargetApks || saveToVault),
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
            .testTag("create_and_sign_custom_button")
    ) {
        Text(
            text = if (hasTargetApks) strings.createAndSignButton else strings.saveToVaultLabel,
            maxLines = 1,
            softWrap = false
        )
    }
}

@Composable
private fun ImportKeystoreTab(
    strings: UiStrings,
    onPickImportKeystoreFile: (storePassword: String, keyPassword: String) -> Unit
) {
    var storePassword by rememberSaveable { mutableStateOf("android") }
    var keyPassword by rememberSaveable { mutableStateOf("") }

    OutlinedTextField(
        value = storePassword,
        onValueChange = { storePassword = it },
        label = { Text(strings.importStorePassLabel) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("import_store_password_input")
    )
    OutlinedTextField(
        value = keyPassword,
        onValueChange = { keyPassword = it },
        label = { Text(strings.importKeyPassLabel) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("import_key_password_input")
    )

    OutlinedButton(
        onClick = { onPickImportKeystoreFile(storePassword, keyPassword) },
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
            .testTag("pick_import_keystore_button")
    ) {
        Icon(Icons.Filled.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(strings.importPickFileButton, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}
