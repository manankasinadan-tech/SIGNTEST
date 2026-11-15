package com.example

import android.Manifest
import android.app.Activity
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.api.DocumentationPdfGenerator
import com.example.api.SignerApiContract
import com.example.crypto.ReportFormatter
import com.example.model.AppLanguage
import com.example.ui.SignerScreen
import com.example.ui.SignerViewModel
import com.example.ui.stringsFor
import com.example.ui.theme.SignerLabTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private val viewModel: SignerViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (savedInstanceState == null) {
            dispatchIncomingIntent(intent)
        }
        setContent {
            SignerLabTheme {
                val language by viewModel.language.collectAsStateWithLifecycle()
                val permissionState by viewModel.permissionState.collectAsStateWithLifecycle()
                val selectedApks by viewModel.selectedApks.collectAsStateWithLifecycle()
                val fileBrowserState by viewModel.fileBrowserState.collectAsStateWithLifecycle()
                val verificationState by viewModel.verificationState.collectAsStateWithLifecycle()
                val pendingExternal by viewModel.pendingExternalResult.collectAsStateWithLifecycle()

                val strings = stringsFor(language)
                val snackbarHostState = remember { SnackbarHostState() }
                val scope = rememberCoroutineScope()
                val lifecycleOwner = LocalLifecycleOwner.current

                // Deliver result back to external calling app when requested
                LaunchedEffect(pendingExternal) {
                    val res = pendingExternal ?: return@LaunchedEffect
                    val resultIntent = Intent().apply {
                        if (res.reports != null && res.reports.isNotEmpty()) {
                            val primary = res.reports.first()
                            putExtra(SignerApiContract.RESULT_IS_VERIFIED, res.reports.all { it.isVerified })
                            putStringArrayListExtra(
                                SignerApiContract.RESULT_DETECTED_SCHEMES,
                                ArrayList(primary.detectedSchemes.map { it.label })
                            )
                            putStringArrayListExtra(
                                SignerApiContract.RESULT_VERIFIED_SCHEMES,
                                ArrayList(primary.verifiedSchemes.map { it.label })
                            )
                            putStringArrayListExtra(
                                SignerApiContract.RESULT_CERT_SHA256_LIST,
                                ArrayList(primary.certificates.map { it.sha256 })
                            )
                            primary.packageName?.let { putExtra(SignerApiContract.RESULT_PACKAGE_NAME, it) }
                            putExtra(SignerApiContract.RESULT_JSON, ReportFormatter.formatJson(res.reports))
                            putExtra(
                                SignerApiContract.RESULT_TEXT,
                                ReportFormatter.formatBatchPlainText(res.reports, res.language)
                            )
                        } else {
                            putExtra(SignerApiContract.RESULT_IS_VERIFIED, false)
                            res.errorMessage?.let { putExtra(SignerApiContract.RESULT_ERROR, it) }
                        }
                    }
                    setResult(Activity.RESULT_OK, resultIntent)
                    viewModel.consumePendingExternalResult()
                    if (res.silentReturn) {
                        finish()
                    }
                }

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

                val legacyStorageLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.RequestPermission()
                ) {
                    viewModel.refreshPermissions()
                }

                val manageAllFilesLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.StartActivityForResult()
                ) {
                    viewModel.refreshPermissions()
                }

                val safApkLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.OpenMultipleDocuments()
                ) { uris ->
                    viewModel.addSafUris(uris)
                }

                val exportTxtLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.CreateDocument("text/plain")
                ) { uri ->
                    if (uri != null) {
                        val txt = viewModel.buildTxtExportContent() ?: return@rememberLauncherForActivityResult
                        writeTextToUri(uri, txt)
                        scope.launch { snackbarHostState.showSnackbar(strings.exportedToast) }
                    }
                }

                val exportJsonLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.CreateDocument("application/json")
                ) { uri ->
                    if (uri != null) {
                        val json = viewModel.buildJsonExportContent() ?: return@rememberLauncherForActivityResult
                        writeTextToUri(uri, json)
                        scope.launch { snackbarHostState.showSnackbar(strings.exportedToast) }
                    }
                }

                val exportPdfLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.CreateDocument("application/pdf")
                ) { uri ->
                    if (uri != null) {
                        scope.launch {
                            withContext(Dispatchers.IO) {
                                contentResolver.openOutputStream(uri)?.use { out ->
                                    DocumentationPdfGenerator.generate(language, out)
                                }
                            }
                            snackbarHostState.showSnackbar(strings.pdfExportedToast)
                        }
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
                    },
                    onDownloadApiPdf = {
                        exportPdfLauncher.launch("SignerLAB_API_Documentation_${language.code.uppercase()}.pdf")
                    }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        dispatchIncomingIntent(intent)
    }

    @Suppress("DEPRECATION")
    private fun dispatchIncomingIntent(intent: Intent?) {
        if (intent == null) return
        val action = intent.action
        val isCommandIntent = action == SignerApiContract.ACTION_VERIFY_APK ||
            action == Intent.ACTION_VIEW ||
            action == Intent.ACTION_SEND ||
            action == Intent.ACTION_SEND_MULTIPLE
        if (!isCommandIntent) return

        val paths = linkedSetOf<String>()
        val uris = linkedSetOf<Uri>()

        intent.getStringExtra(SignerApiContract.EXTRA_APK_PATH)?.takeIf { it.isNotBlank() }?.let { paths += it }
        intent.getStringArrayListExtra(SignerApiContract.EXTRA_APK_PATHS)?.forEach {
            if (it.isNotBlank()) paths += it
        }

        val dataUri = intent.data
        if (dataUri != null) {
            if (dataUri.scheme == SignerApiContract.DEEP_LINK_SCHEME && dataUri.host == SignerApiContract.DEEP_LINK_HOST) {
                dataUri.getQueryParameter("path")?.takeIf { it.isNotBlank() }?.let { paths += it }
            } else if (dataUri.scheme == "file") {
                dataUri.path?.let { paths += it }
            } else {
                uris += dataUri
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)?.let { uris += it }
            intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)?.forEach { uris += it }
            intent.getParcelableExtra(SignerApiContract.EXTRA_URI, Uri::class.java)?.let { uris += it }
        } else {
            (intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri)?.let { uris += it }
            intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.forEach { uris += it }
            (intent.getParcelableExtra(SignerApiContract.EXTRA_URI) as? Uri)?.let { uris += it }
        }

        intent.clipData?.let { clip ->
            for (i in 0 until clip.itemCount) {
                clip.getItemAt(i).uri?.let { uris += it }
            }
        }

        if (paths.isEmpty() && uris.isEmpty()) return

        val langParam = intent.getStringExtra(SignerApiContract.EXTRA_LANG)
            ?: dataUri?.getQueryParameter("lang")
        val overrideLang = when {
            langParam.equals("en", ignoreCase = true) -> AppLanguage.EN
            langParam.equals("fr", ignoreCase = true) -> AppLanguage.FR
            else -> null
        }

        val autoVerify = intent.getBooleanExtra(
            SignerApiContract.EXTRA_AUTO_VERIFY,
            dataUri?.getQueryParameter("auto")?.toBooleanStrictOrNull() ?: true
        )
        val returnResult = intent.getBooleanExtra(SignerApiContract.EXTRA_RETURN_RESULT, callingActivity != null)
        val silentReturn = intent.getBooleanExtra(SignerApiContract.EXTRA_SILENT_RETURN, false)

        viewModel.handleExternalCommand(
            paths = paths.toList(),
            uris = uris.toList(),
            autoVerify = autoVerify,
            returnResult = returnResult,
            silentReturn = silentReturn,
            overrideLang = overrideLang
        )
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
