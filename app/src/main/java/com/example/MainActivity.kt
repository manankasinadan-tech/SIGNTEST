package com.example

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.ui.SignerScreen
import com.example.ui.SignerViewModel
import com.example.ui.stringsFor
import com.example.ui.theme.SignerLabTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private val viewModel: SignerViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SignerLabTheme {
                val language by viewModel.language.collectAsStateWithLifecycle()
                val permissionState by viewModel.permissionState.collectAsStateWithLifecycle()
                val selectedApks by viewModel.selectedApks.collectAsStateWithLifecycle()
                val fileBrowserState by viewModel.fileBrowserState.collectAsStateWithLifecycle()
                val verificationState by viewModel.verificationState.collectAsStateWithLifecycle()

                val strings = stringsFor(language)
                val snackbarHostState = remember { SnackbarHostState() }
                val scope = rememberCoroutineScope()
                val lifecycleOwner = LocalLifecycleOwner.current

                // Refresh storage/root status automatically when returning from Android Settings
                DisposableEffect(lifecycleOwner) {
                    val observer = LifecycleEventObserver { _, event ->
                        if (event == Lifecycle.Event.ON_RESUME) {
                            viewModel.refreshPermissions()
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
                }

                // Legacy storage permission launcher (Android 7 - 10)
                val legacyStorageLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.RequestPermission()
                ) {
                    viewModel.refreshPermissions()
                }

                // Manage All Files Access settings launcher (Android 11+)
                val manageAllFilesLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.StartActivityForResult()
                ) {
                    viewModel.refreshPermissions()
                }

                // System SAF multi-APK picker fallback
                val safApkLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.OpenMultipleDocuments()
                ) { uris ->
                    viewModel.addSafUris(uris)
                }

                // Export TXT launcher
                val exportTxtLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.CreateDocument("text/plain")
                ) { uri ->
                    if (uri != null) {
                        val txt = viewModel.buildTxtExportContent() ?: return@rememberLauncherForActivityResult
                        writeTextToUri(uri, txt)
                        scope.launch { snackbarHostState.showSnackbar(strings.exportedToast) }
                    }
                }

                // Export JSON launcher
                val exportJsonLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.CreateDocument("application/json")
                ) { uri ->
                    if (uri != null) {
                        val json = viewModel.buildJsonExportContent() ?: return@rememberLauncherForActivityResult
                        writeTextToUri(uri, json)
                        scope.launch { snackbarHostState.showSnackbar(strings.exportedToast) }
                    }
                }

                SignerScreen(
                    language = language,
                    permissionState = permissionState,
                    selectedApks = selectedApks,
                    fileBrowserState = fileBrowserState,
                    verificationState = verificationState,
                    shortcuts = remember { viewModel.getShortcutPaths() },
                    snackbarHostState = snackbarHostState,
                    onLanguageChange = viewModel::setLanguage,
                    onRequestStoragePermission = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            try {
                                val intent = Intent(
                                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                    Uri.parse("package:$packageName")
                                )
                                manageAllFilesLauncher.launch(intent)
                            } catch (_: Exception) {
                                val fallback = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                                manageAllFilesLauncher.launch(fallback)
                            }
                        } else {
                            legacyStorageLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                        }
                    },
                    onRequestRootPermission = {
                        viewModel.requestRootAccess(alsoEnableRootBrowser = false)
                    },
                    onRefreshPermissions = viewModel::refreshPermissions,
                    onOpenFilePicker = viewModel::openFileBrowser,
                    onDismissFilePicker = viewModel::closeFileBrowser,
                    onNavigateFolder = viewModel::navigateToDirectory,
                    onNavigateUp = viewModel::navigateUp,
                    onToggleRootBrowse = viewModel::toggleRootBrowserMode,
                    onSearchBrowser = viewModel::updateBrowserSearchQuery,
                    onToggleBrowserEntry = viewModel::toggleFileSelection,
                    onSelectAllVisibleApks = viewModel::selectAllVisibleApks,
                    onClearBrowserSelection = viewModel::clearBrowserSelection,
                    onOpenSystemSaf = {
                        safApkLauncher.launch(
                            arrayOf(
                                "application/vnd.android.package-archive",
                                "application/octet-stream",
                                "*/*"
                            )
                        )
                    },
                    onConfirmBrowserSelection = viewModel::confirmBrowserSelection,
                    onRemoveSelectedApk = viewModel::removeSelectedApk,
                    onClearSelectedApks = viewModel::clearSelectedApks,
                    onVerifyClick = viewModel::verifySelectedApks,
                    onSelectReportTab = viewModel::selectReportIndex,
                    onCopyText = { text ->
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("SignerLAB", text))
                        scope.launch { snackbarHostState.showSnackbar(strings.copiedToast) }
                    },
                    onExportTxt = {
                        exportTxtLauncher.launch("signerlab_report_${System.currentTimeMillis()}.txt")
                    },
                    onExportJson = {
                        exportJsonLauncher.launch("signerlab_report_${System.currentTimeMillis()}.json")
                    }
                )
            }
        }
    }

    private fun writeTextToUri(uri: Uri, content: String) {
        try {
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(content.toByteArray(Charsets.UTF_8))
            }
        } catch (_: Exception) {
        }
    }
}
