package com.example.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Draw
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SdStorage
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.AospKeyProfile
import com.example.model.ApkVerificationReport
import com.example.model.AppLanguage
import com.example.model.ClonedKeySpec
import com.example.model.CustomKeyCreationSpec
import com.example.model.MainTab
import com.example.model.PartitionAuditUiState
import com.example.model.PartitionResignPlan
import com.example.model.PartitionResignUiState
import com.example.model.PermissionState
import com.example.model.RootStatus
import com.example.model.SelectedApkItem
import com.example.model.SignedApkResult
import com.example.model.SigningOptions
import com.example.model.SigningUiState
import com.example.model.StoredKeyEntry
import com.example.model.VerificationUiState
import com.example.ui.theme.LocalSemanticColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignerScreen(
    language: AppLanguage,
    activeTab: MainTab,
    permissionState: PermissionState,
    selectedApks: List<SelectedApkItem>,
    resignSelectedApks: List<SelectedApkItem>,
    fileBrowserState: FileBrowserState,
    verificationState: VerificationUiState,
    selectedAospProfile: AospKeyProfile,
    signingOptions: SigningOptions,
    signingState: SigningUiState,
    vaultKeys: List<StoredKeyEntry>,
    showCustomKeyDialog: Boolean,
    keyUpdaterSpec: ClonedKeySpec?,
    partitionSelectedDir: String,
    partitionAuditState: PartitionAuditUiState,
    partitionResignState: PartitionResignUiState,
    showVerifyBeforeResignDialog: Boolean,
    showGsiResignStrategyDialog: Boolean,
    shortcuts: Map<String, String>,
    snackbarHostState: SnackbarHostState,
    onLanguageChange: (AppLanguage) -> Unit,
    onTabChange: (MainTab) -> Unit,
    onRequestStoragePermission: () -> Unit,
    onRequestRootPermission: () -> Unit,
    onRefreshPermissions: () -> Unit,
    onOpenFilePicker: (MainTab) -> Unit,
    onDismissFilePicker: () -> Unit,
    onNavigateFolder: (String, Boolean?) -> Unit,
    onNavigateUp: () -> Unit,
    onToggleRootBrowse: () -> Unit,
    onSearchBrowser: (String) -> Unit,
    onToggleBrowserEntry: (com.example.model.FileEntry) -> Unit,
    onSelectAllVisibleApks: () -> Unit,
    onClearBrowserSelection: () -> Unit,
    onOpenSystemSaf: () -> Unit,
    onConfirmBrowserSelection: () -> Unit,
    onRemoveSelectedApk: (String) -> Unit,
    onClearSelectedApks: () -> Unit,
    onVerifyClick: () -> Unit,
    onSelectReportTab: (Int) -> Unit,
    onCopyText: (String) -> Unit,
    onExportTxt: () -> Unit,
    onExportJson: () -> Unit,
    onDownloadApiPdf: () -> Unit,
    onRemoveResignApk: (String) -> Unit,
    onClearResignApks: () -> Unit,
    onSelectAospProfile: (AospKeyProfile) -> Unit,
    onUpdateSigningOptions: (SigningOptions) -> Unit,
    onSignWithAospClick: () -> Unit,
    onOpenCustomKeyDialog: () -> Unit,
    onDismissCustomKeyDialog: () -> Unit,
    onCreateCustomKeyAndSign: (CustomKeyCreationSpec) -> Unit,
    onSignWithVaultKey: (StoredKeyEntry, String) -> Unit,
    onExportVaultKey: (StoredKeyEntry) -> Unit,
    onDeleteVaultKey: (String) -> Unit,
    onPickImportKeystoreFile: (storePassword: String, keyPassword: String) -> Unit,
    onPrepareKeyUpdater: () -> Unit,
    onUpdateKeyUpdaterSpec: (ClonedKeySpec) -> Unit,
    onDismissKeyUpdater: () -> Unit,
    onSaveClonedKeyOnly: (ClonedKeySpec) -> Unit,
    onGenerateClonedAndResign: (ClonedKeySpec) -> Unit,
    onInspectSignedReport: (SignedApkResult) -> Unit,
    onSaveSignedApkAs: (SignedApkResult) -> Unit,
    onClearPartitionDir: () -> Unit,
    onVerifyPartition: () -> Unit,
    onResignPartitionClick: () -> Unit,
    onDismissVerifyBeforeResign: () -> Unit,
    onVerifyFromGateDialog: () -> Unit,
    onDismissGsiStrategyDialog: () -> Unit,
    onExecuteGsiResignPlan: (PartitionResignPlan) -> Unit,
    onInspectPartitionApkReport: (ApkVerificationReport) -> Unit
) {
    val strings = stringsFor(language)
    var showHelpDialog by rememberSaveable { mutableStateOf(false) }

    BackHandler(enabled = activeTab != MainTab.VERIFY) {
        onTabChange(MainTab.VERIFY)
    }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                ),
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            shape = MaterialTheme.shapes.small,
                            color = MaterialTheme.colorScheme.primaryContainer,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = Icons.Filled.Shield,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "SignerLAB",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1
                            )
                            Text(
                                text = strings.appSubtitle,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showHelpDialog = true },
                        modifier = Modifier.testTag("help_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                            contentDescription = strings.helpTooltip,
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    SingleChoiceSegmentedButtonRow(
                        modifier = Modifier.padding(end = 10.dp)
                    ) {
                        AppLanguage.entries.forEachIndexed { idx, lang ->
                            SegmentedButton(
                                selected = language == lang,
                                onClick = { onLanguageChange(lang) },
                                shape = SegmentedButtonDefaults.itemShape(
                                    index = idx,
                                    count = AppLanguage.entries.size
                                ),
                                modifier = Modifier.testTag("lang_toggle_${lang.code}")
                            ) {
                                Text(
                                    text = lang.label,
                                    style = MaterialTheme.typography.labelMedium,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            PrimaryTabRow(
                selectedTabIndex = when (activeTab) {
                    MainTab.VERIFY -> 0
                    MainTab.RESIGN -> 1
                    MainTab.PARTITION -> 2
                },
                containerColor = MaterialTheme.colorScheme.background
            ) {
                Tab(
                    selected = activeTab == MainTab.VERIFY,
                    onClick = { onTabChange(MainTab.VERIFY) },
                    icon = { Icon(Icons.Filled.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp)) },
                    text = { Text(strings.tabVerify, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                    modifier = Modifier.testTag("main_tab_verify")
                )
                Tab(
                    selected = activeTab == MainTab.RESIGN,
                    onClick = { onTabChange(MainTab.RESIGN) },
                    icon = { Icon(Icons.Filled.Draw, contentDescription = null, modifier = Modifier.size(18.dp)) },
                    text = { Text(strings.tabResign, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                    modifier = Modifier.testTag("main_tab_resign")
                )
                Tab(
                    selected = activeTab == MainTab.PARTITION,
                    onClick = { onTabChange(MainTab.PARTITION) },
                    icon = { Icon(Icons.Filled.AccountTree, contentDescription = null, modifier = Modifier.size(18.dp)) },
                    text = { Text(strings.tabPartition, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                    modifier = Modifier.testTag("main_tab_partition")
                )
            }

            BoxWithConstraints(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                val isExpanded = maxWidth >= 840.dp

                if (isExpanded) {
                    Row(
                        modifier = Modifier.fillMaxSize(),
                        horizontalArrangement = Arrangement.spacedBy(20.dp)
                    ) {
                        Column(
                            modifier = Modifier
                                .weight(0.44f)
                                .fillMaxHeight()
                                .verticalScroll(rememberScrollState())
                                .padding(vertical = 12.dp),
                            verticalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            PermissionStripCard(
                                permissionState = permissionState,
                                strings = strings,
                                onActivateStorage = onRequestStoragePermission,
                                onActivateRoot = onRequestRootPermission,
                                onRefresh = onRefreshPermissions
                            )
                            when (activeTab) {
                                MainTab.VERIFY -> {
                                    VerifyControlsCard(
                                        selectedApks = selectedApks,
                                        verificationState = verificationState,
                                        strings = strings,
                                        onOpenFilePicker = { onOpenFilePicker(MainTab.VERIFY) },
                                        onRemoveSelectedApk = onRemoveSelectedApk,
                                        onClearSelectedApks = onClearSelectedApks,
                                        onVerifyClick = onVerifyClick
                                    )
                                }
                                MainTab.RESIGN -> {
                                    ResignControlsColumn(
                                        selectedApks = resignSelectedApks,
                                        selectedAospProfile = selectedAospProfile,
                                        signingOptions = signingOptions,
                                        signingState = signingState,
                                        strings = strings,
                                        onOpenFilePicker = { onOpenFilePicker(MainTab.RESIGN) },
                                        onRemoveApk = onRemoveResignApk,
                                        onClearApks = onClearResignApks,
                                        onSelectAospProfile = onSelectAospProfile,
                                        onUpdateOptions = onUpdateSigningOptions,
                                        onSignWithAospClick = onSignWithAospClick,
                                        onSignWithCustomClick = onOpenCustomKeyDialog,
                                        onKeyUpdaterClick = onPrepareKeyUpdater
                                    )
                                }
                                MainTab.PARTITION -> {
                                    PartitionControlsCard(
                                        selectedDirPath = partitionSelectedDir,
                                        auditState = partitionAuditState,
                                        resignState = partitionResignState,
                                        strings = strings,
                                        onOpenDirectoryPicker = { onOpenFilePicker(MainTab.PARTITION) },
                                        onClearDir = onClearPartitionDir,
                                        onVerifyPartition = onVerifyPartition,
                                        onResignPartitionClick = onResignPartitionClick
                                    )
                                }
                            }
                        }
                        Column(
                            modifier = Modifier
                                .weight(0.56f)
                                .fillMaxHeight()
                                .verticalScroll(rememberScrollState())
                                .padding(vertical = 12.dp)
                        ) {
                            when (activeTab) {
                                MainTab.VERIFY -> {
                                    ResultsAreaContent(
                                        verificationState = verificationState,
                                        language = language,
                                        strings = strings,
                                        onSelectReportTab = onSelectReportTab,
                                        onCopyText = onCopyText,
                                        onExportTxt = onExportTxt,
                                        onExportJson = onExportJson
                                    )
                                }
                                MainTab.RESIGN -> {
                                    ResignResultsArea(
                                        signingState = signingState,
                                        strings = strings,
                                        onInspectReport = onInspectSignedReport,
                                        onSaveSignedApkAs = onSaveSignedApkAs
                                    )
                                }
                                MainTab.PARTITION -> {
                                    PartitionDashboardArea(
                                        auditState = partitionAuditState,
                                        resignState = partitionResignState,
                                        strings = strings,
                                        onInspectApkReport = onInspectPartitionApkReport
                                    )
                                }
                            }
                        }
                    }
                } else {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(vertical = 10.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        PermissionStripCard(
                            permissionState = permissionState,
                            strings = strings,
                            onActivateStorage = onRequestStoragePermission,
                            onActivateRoot = onRequestRootPermission,
                            onRefresh = onRefreshPermissions
                        )
                        when (activeTab) {
                            MainTab.VERIFY -> {
                                VerifyControlsCard(
                                    selectedApks = selectedApks,
                                    verificationState = verificationState,
                                    strings = strings,
                                    onOpenFilePicker = { onOpenFilePicker(MainTab.VERIFY) },
                                    onRemoveSelectedApk = onRemoveSelectedApk,
                                    onClearSelectedApks = onClearSelectedApks,
                                    onVerifyClick = onVerifyClick
                                )
                                ResultsAreaContent(
                                    verificationState = verificationState,
                                    language = language,
                                    strings = strings,
                                    onSelectReportTab = onSelectReportTab,
                                    onCopyText = onCopyText,
                                    onExportTxt = onExportTxt,
                                    onExportJson = onExportJson
                                )
                            }
                            MainTab.RESIGN -> {
                                ResignControlsColumn(
                                    selectedApks = resignSelectedApks,
                                    selectedAospProfile = selectedAospProfile,
                                    signingOptions = signingOptions,
                                    signingState = signingState,
                                    strings = strings,
                                    onOpenFilePicker = { onOpenFilePicker(MainTab.RESIGN) },
                                    onRemoveApk = onRemoveResignApk,
                                    onClearApks = onClearResignApks,
                                    onSelectAospProfile = onSelectAospProfile,
                                    onUpdateOptions = onUpdateSigningOptions,
                                    onSignWithAospClick = onSignWithAospClick,
                                    onSignWithCustomClick = onOpenCustomKeyDialog,
                                    onKeyUpdaterClick = onPrepareKeyUpdater
                                )
                                ResignResultsArea(
                                    signingState = signingState,
                                    strings = strings,
                                    onInspectReport = onInspectSignedReport,
                                    onSaveSignedApkAs = onSaveSignedApkAs
                                )
                            }
                            MainTab.PARTITION -> {
                                PartitionControlsCard(
                                    selectedDirPath = partitionSelectedDir,
                                    auditState = partitionAuditState,
                                    resignState = partitionResignState,
                                    strings = strings,
                                    onOpenDirectoryPicker = { onOpenFilePicker(MainTab.PARTITION) },
                                    onClearDir = onClearPartitionDir,
                                    onVerifyPartition = onVerifyPartition,
                                    onResignPartitionClick = onResignPartitionClick
                                )
                                PartitionDashboardArea(
                                    auditState = partitionAuditState,
                                    resignState = partitionResignState,
                                    strings = strings,
                                    onInspectApkReport = onInspectPartitionApkReport
                                )
                            }
                        }
                        Spacer(Modifier.height(16.dp))
                    }
                }
            }
        }
    }

    if (fileBrowserState.isOpen) {
        FileManagerPopupDialog(
            state = fileBrowserState,
            permissionState = permissionState,
            shortcuts = shortcuts,
            strings = strings,
            onDismiss = onDismissFilePicker,
            onNavigate = onNavigateFolder,
            onNavigateUp = onNavigateUp,
            onToggleRootMode = onToggleRootBrowse,
            onSearchChange = onSearchBrowser,
            onToggleEntry = onToggleBrowserEntry,
            onSelectAllVisible = onSelectAllVisibleApks,
            onClearSelection = onClearBrowserSelection,
            onOpenSystemSaf = onOpenSystemSaf,
            onConfirm = onConfirmBrowserSelection
        )
    }

    if (showCustomKeyDialog) {
        CustomKeyVaultDialog(
            vaultKeys = vaultKeys,
            hasTargetApks = resignSelectedApks.isNotEmpty(),
            strings = strings,
            onDismiss = onDismissCustomKeyDialog,
            onSignWithVaultKey = onSignWithVaultKey,
            onExportVaultKey = onExportVaultKey,
            onDeleteVaultKey = onDeleteVaultKey,
            onCreateCustomKey = onCreateCustomKeyAndSign,
            onPickImportKeystoreFile = onPickImportKeystoreFile
        )
    }

    if (keyUpdaterSpec != null) {
        KeyUpdaterDialog(
            spec = keyUpdaterSpec,
            strings = strings,
            onUpdateSpec = onUpdateKeyUpdaterSpec,
            onDismiss = onDismissKeyUpdater,
            onSaveKeyOnly = onSaveClonedKeyOnly,
            onGenerateAndResign = onGenerateClonedAndResign
        )
    }

    if (showHelpDialog) {
        HelpDocumentationDialog(
            language = language,
            strings = strings,
            onDismiss = { showHelpDialog = false },
            onDownloadPdf = onDownloadApiPdf,
            onCopySnippet = onCopyText
        )
    }

    if (showVerifyBeforeResignDialog) {
        VerifyBeforeResignDialog(
            strings = strings,
            onDismiss = onDismissVerifyBeforeResign,
            onVerifyNow = onVerifyFromGateDialog
        )
    }

    val verifiedAudit = (partitionAuditState as? PartitionAuditUiState.Verified)?.report
    if (showGsiResignStrategyDialog && verifiedAudit != null) {
        GsiResignStrategyDialog(
            auditReport = verifiedAudit,
            vaultKeys = vaultKeys,
            strings = strings,
            onDismiss = onDismissGsiStrategyDialog,
            onConfirmPlan = onExecuteGsiResignPlan
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun VerifyControlsCard(
    selectedApks: List<SelectedApkItem>,
    verificationState: VerificationUiState,
    strings: UiStrings,
    onOpenFilePicker: () -> Unit,
    onRemoveSelectedApk: (String) -> Unit,
    onClearSelectedApks: () -> Unit,
    onVerifyClick: () -> Unit
) {

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
                Text(
                    text = strings.apkFieldLabel,
                    style = MaterialTheme.typography.titleSmall
                )
                if (selectedApks.isNotEmpty()) {
                    TextButton(
                        onClick = onClearSelectedApks,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
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
                    .clickable(onClick = onOpenFilePicker)
                    .testTag("apk_picker_field")
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
                            onClick = { onRemoveSelectedApk(apk.id) },
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

            val isAnalyzing = verificationState is VerificationUiState.Analyzing
            Button(
                onClick = onVerifyClick,
                enabled = selectedApks.isNotEmpty() && !isAnalyzing,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .testTag("verify_button")
            ) {
                if (isAnalyzing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(Modifier.width(10.dp))
                    val analyzing = verificationState as VerificationUiState.Analyzing
                    Text(
                        text = strings.verifyingProgress(
                            analyzing.currentIndex,
                            analyzing.totalCount,
                            analyzing.currentFileName
                        ),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                } else {
                    Icon(Icons.Filled.VerifiedUser, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = strings.verifyButton,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            }
        }
    }
}

@Composable
private fun PermissionStripCard(
    permissionState: PermissionState,
    strings: UiStrings,
    onActivateStorage: () -> Unit,
    onActivateRoot: () -> Unit,
    onRefresh: () -> Unit
) {
    val semantic = LocalSemanticColors.current

    Surface(
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val storageActive = permissionState.hasStorageAccess
            Surface(
                shape = MaterialTheme.shapes.small,
                color = if (storageActive) semantic.verifiedContainer else MaterialTheme.colorScheme.surfaceVariant,
                border = BorderStroke(
                    1.dp,
                    if (storageActive) semantic.verified.copy(alpha = 0.4f) else MaterialTheme.colorScheme.outline
                ),
                modifier = Modifier
                    .weight(1f)
                    .minimumInteractiveComponentSize()
                    .clickable(onClick = onActivateStorage)
                    .testTag("storage_permission_toggle")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (storageActive) Icons.Filled.CheckCircle else Icons.Filled.SdStorage,
                        contentDescription = null,
                        tint = if (storageActive) semantic.verified else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(strings.storageLabel, style = MaterialTheme.typography.labelMedium)
                        Text(
                            text = if (storageActive) strings.granted else strings.activate,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (storageActive) semantic.verified else MaterialTheme.colorScheme.primary,
                            maxLines = 1
                        )
                    }
                }
            }

            val rootGranted = permissionState.rootStatus == RootStatus.GRANTED
            val rootStatusText = when (permissionState.rootStatus) {
                RootStatus.GRANTED -> strings.granted
                RootStatus.CHECKING -> strings.checking
                RootStatus.DENIED -> strings.denied
                RootStatus.UNAVAILABLE -> strings.unavailable
                RootStatus.UNKNOWN -> strings.activate
            }
            val rootTint = when (permissionState.rootStatus) {
                RootStatus.GRANTED -> semantic.verified
                RootStatus.DENIED -> MaterialTheme.colorScheme.error
                RootStatus.UNAVAILABLE -> MaterialTheme.colorScheme.onSurfaceVariant
                else -> MaterialTheme.colorScheme.primary
            }
            Surface(
                shape = MaterialTheme.shapes.small,
                color = if (rootGranted) semantic.verifiedContainer else MaterialTheme.colorScheme.surfaceVariant,
                border = BorderStroke(
                    1.dp,
                    if (rootGranted) semantic.verified.copy(alpha = 0.4f) else MaterialTheme.colorScheme.outline
                ),
                modifier = Modifier
                    .weight(1f)
                    .minimumInteractiveComponentSize()
                    .clickable(
                        enabled = permissionState.rootStatus != RootStatus.CHECKING,
                        onClick = onActivateRoot
                    )
                    .testTag("root_permission_toggle")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (rootGranted) Icons.Filled.CheckCircle else Icons.Filled.AdminPanelSettings,
                        contentDescription = null,
                        tint = rootTint,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(strings.rootLabel, style = MaterialTheme.typography.labelMedium)
                        Text(
                            text = rootStatusText,
                            style = MaterialTheme.typography.bodySmall,
                            color = rootTint,
                            maxLines = 1
                        )
                    }
                }
            }

            IconButton(
                onClick = onRefresh,
                modifier = Modifier.testTag("refresh_permissions_button")
            ) {
                Icon(
                    imageVector = Icons.Filled.Refresh,
                    contentDescription = strings.refresh,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun ResultsAreaContent(
    verificationState: VerificationUiState,
    language: AppLanguage,
    strings: UiStrings,
    onSelectReportTab: (Int) -> Unit,
    onCopyText: (String) -> Unit,
    onExportTxt: () -> Unit,
    onExportJson: () -> Unit
) {
    when (verificationState) {
        is VerificationUiState.Idle -> {
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
                        imageVector = Icons.Filled.Shield,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f),
                        modifier = Modifier.size(40.dp)
                    )
                    Text(
                        text = strings.emptyTitle,
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = strings.emptyBody,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        is VerificationUiState.Analyzing -> {
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
                        text = strings.verifyingProgress(
                            verificationState.currentIndex,
                            verificationState.totalCount,
                            verificationState.currentFileName
                        ),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }

        is VerificationUiState.Error -> {
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
                        text = verificationState.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }

        is VerificationUiState.Success -> {
            ReportResultSection(
                reports = verificationState.reports,
                selectedIndex = verificationState.selectedReportIndex,
                language = language,
                strings = strings,
                onSelectReport = onSelectReportTab,
                onCopyText = onCopyText,
                onExportTxt = onExportTxt,
                onExportJson = onExportJson
            )
        }
    }
}
