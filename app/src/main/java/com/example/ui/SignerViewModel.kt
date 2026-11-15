package com.example.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.crypto.AospKeyProvider
import com.example.crypto.ApkReSigner
import com.example.crypto.ApkSignatureAnalyzer
import com.example.crypto.KeyCloner
import com.example.crypto.KeystoreManager
import com.example.crypto.ReportFormatter
import com.example.data.FileBrowserRepository
import com.example.data.LanguagePreferences
import com.example.data.RootShellService
import com.example.model.AospKeyProfile
import com.example.model.ApkSourceType
import com.example.model.ApkVerificationReport
import com.example.model.AppLanguage
import com.example.model.ClonedKeySpec
import com.example.model.CustomKeyCreationSpec
import com.example.model.FileEntry
import com.example.model.MainTab
import com.example.model.PermissionState
import com.example.model.RootStatus
import com.example.model.SelectedApkItem
import com.example.model.SignedApkResult
import com.example.model.SigningOptions
import com.example.model.SigningUiState
import com.example.model.StoredKeyEntry
import com.example.model.VerificationUiState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class FileBrowserState(
    val isOpen: Boolean = false,
    val currentPath: String = "/storage/emulated/0",
    val entries: List<FileEntry> = emptyList(),
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val searchQuery: String = "",
    val useRootMode: Boolean = false,
    val checkedPaths: Set<String> = emptySet(),
    val cachedEntriesByPath: Map<String, FileEntry> = emptyMap()
)

data class PendingExternalCommandResult(
    val reports: List<ApkVerificationReport>?,
    val errorMessage: String?,
    val silentReturn: Boolean,
    val language: AppLanguage
)

class SignerViewModel(application: Application) : AndroidViewModel(application) {

    private val languagePrefs = LanguagePreferences(application)
    private val fileRepo = FileBrowserRepository(application)
    private val analyzer = ApkSignatureAnalyzer(application)
    private val aospKeyProvider = AospKeyProvider(application)
    private val keystoreManager = KeystoreManager(application)
    private val apkReSigner = ApkReSigner(application)

    val language: StateFlow<AppLanguage> = languagePrefs.languageFlow
        .stateIn(viewModelScope, SharingStarted.Eagerly, AppLanguage.FR)

    private val _activeTab = MutableStateFlow(MainTab.VERIFY)
    val activeTab: StateFlow<MainTab> = _activeTab.asStateFlow()

    private val _permissionState = MutableStateFlow(
        PermissionState(
            hasStorageAccess = fileRepo.hasStoragePermission(),
            rootStatus = if (RootShellService.hasSuBinary()) RootStatus.UNKNOWN else RootStatus.UNAVAILABLE
        )
    )
    val permissionState: StateFlow<PermissionState> = _permissionState.asStateFlow()

    private val _selectedApks = MutableStateFlow<List<SelectedApkItem>>(emptyList())
    val selectedApks: StateFlow<List<SelectedApkItem>> = _selectedApks.asStateFlow()

    private val _resignSelectedApks = MutableStateFlow<List<SelectedApkItem>>(emptyList())
    val resignSelectedApks: StateFlow<List<SelectedApkItem>> = _resignSelectedApks.asStateFlow()

    private var browserTargetTab: MainTab = MainTab.VERIFY

    private val _fileBrowserState = MutableStateFlow(
        FileBrowserState(currentPath = fileRepo.getDefaultInternalPath())
    )
    val fileBrowserState: StateFlow<FileBrowserState> = _fileBrowserState.asStateFlow()

    private val _verificationState = MutableStateFlow<VerificationUiState>(VerificationUiState.Idle)
    val verificationState: StateFlow<VerificationUiState> = _verificationState.asStateFlow()

    private val _selectedAospProfile = MutableStateFlow(AospKeyProfile.TESTKEY)
    val selectedAospProfile: StateFlow<AospKeyProfile> = _selectedAospProfile.asStateFlow()

    private val _signingOptions = MutableStateFlow(SigningOptions())
    val signingOptions: StateFlow<SigningOptions> = _signingOptions.asStateFlow()

    private val _signingState = MutableStateFlow<SigningUiState>(SigningUiState.Idle)
    val signingState: StateFlow<SigningUiState> = _signingState.asStateFlow()

    private val _vaultKeys = MutableStateFlow(keystoreManager.listKeys())
    val vaultKeys: StateFlow<List<StoredKeyEntry>> = _vaultKeys.asStateFlow()

    private val _showCustomKeyDialog = MutableStateFlow(false)
    val showCustomKeyDialog: StateFlow<Boolean> = _showCustomKeyDialog.asStateFlow()

    private val _keyUpdaterSpec = MutableStateFlow<ClonedKeySpec?>(null)
    val keyUpdaterSpec: StateFlow<ClonedKeySpec?> = _keyUpdaterSpec.asStateFlow()

    private val _pendingExternalResult = MutableStateFlow<PendingExternalCommandResult?>(null)
    val pendingExternalResult: StateFlow<PendingExternalCommandResult?> = _pendingExternalResult.asStateFlow()

    fun setActiveTab(tab: MainTab) {
        _activeTab.value = tab
    }

    fun setLanguage(lang: AppLanguage) {
        viewModelScope.launch {
            languagePrefs.setLanguage(lang)
        }
    }

    fun consumePendingExternalResult() {
        _pendingExternalResult.value = null
    }

    fun refreshPermissions() {
        val hasStorage = fileRepo.hasStoragePermission()
        val currentRoot = _permissionState.value.rootStatus
        val updatedRoot = if (currentRoot == RootStatus.GRANTED) {
            RootStatus.GRANTED
        } else if (RootShellService.hasSuBinary()) {
            if (currentRoot == RootStatus.UNAVAILABLE) RootStatus.UNKNOWN else currentRoot
        } else {
            RootStatus.UNAVAILABLE
        }
        _permissionState.update {
            it.copy(hasStorageAccess = hasStorage, rootStatus = updatedRoot)
        }
    }

    fun requestRootAccess(alsoEnableRootBrowser: Boolean = false) {
        if (_permissionState.value.rootStatus == RootStatus.CHECKING) return
        _permissionState.update { it.copy(rootStatus = RootStatus.CHECKING) }
        viewModelScope.launch {
            val (status, identity) = RootShellService.requestRootAccess()
            _permissionState.update {
                it.copy(rootStatus = status, rootIdentity = identity)
            }
            if (status == RootStatus.GRANTED && alsoEnableRootBrowser) {
                _fileBrowserState.update { it.copy(useRootMode = true) }
                loadDirectory(_fileBrowserState.value.currentPath, useRoot = true)
            }
        }
    }

    fun openFileBrowser(forTab: MainTab = _activeTab.value) {
        browserTargetTab = forTab
        refreshPermissions()
        val currentSelection = if (forTab == MainTab.RESIGN) {
            _resignSelectedApks.value
        } else {
            _selectedApks.value
        }
        val preChecked = currentSelection
            .filter { it.sourceType != ApkSourceType.CONTENT_URI }
            .map { it.originalPath }
            .toSet()
        val startPath = _fileBrowserState.value.currentPath.ifBlank {
            fileRepo.getDefaultInternalPath()
        }
        _fileBrowserState.update {
            it.copy(
                isOpen = true,
                searchQuery = "",
                checkedPaths = preChecked,
                errorMessage = null
            )
        }
        loadDirectory(startPath, _fileBrowserState.value.useRootMode)
    }

    fun closeFileBrowser() {
        _fileBrowserState.update { it.copy(isOpen = false) }
    }

    fun navigateToDirectory(path: String, forceRoot: Boolean? = null) {
        val useRoot = forceRoot ?: _fileBrowserState.value.useRootMode
        if (useRoot && _permissionState.value.rootStatus != RootStatus.GRANTED) {
            _fileBrowserState.update { it.copy(currentPath = path) }
            requestRootAccess(alsoEnableRootBrowser = true)
            return
        }
        _fileBrowserState.update { it.copy(useRootMode = useRoot) }
        loadDirectory(path, useRoot)
    }

    fun navigateUp() {
        val current = _fileBrowserState.value.currentPath.trimEnd('/')
        if (current.isEmpty() || current == "/") return
        val parent = current.substringBeforeLast('/', "")
        val target = if (parent.isEmpty()) "/" else parent
        val needsRoot = target == "/" || target.startsWith("/data") || target.startsWith("/system")
        if (needsRoot && _permissionState.value.rootStatus == RootStatus.GRANTED) {
            navigateToDirectory(target, forceRoot = true)
        } else {
            navigateToDirectory(target, forceRoot = _fileBrowserState.value.useRootMode)
        }
    }

    fun toggleRootBrowserMode() {
        val currentlyRoot = _fileBrowserState.value.useRootMode
        if (!currentlyRoot && _permissionState.value.rootStatus != RootStatus.GRANTED) {
            requestRootAccess(alsoEnableRootBrowser = true)
            return
        }
        val nextRoot = !currentlyRoot
        _fileBrowserState.update { it.copy(useRootMode = nextRoot) }
        loadDirectory(_fileBrowserState.value.currentPath, useRoot = nextRoot)
    }

    fun updateBrowserSearchQuery(query: String) {
        _fileBrowserState.update { it.copy(searchQuery = query) }
    }

    fun toggleFileSelection(entry: FileEntry) {
        if (entry.isDirectory) return
        _fileBrowserState.update { state ->
            val next = state.checkedPaths.toMutableSet()
            if (!next.add(entry.path)) {
                next.remove(entry.path)
            }
            val cache = state.cachedEntriesByPath.toMutableMap()
            cache[entry.path] = entry
            state.copy(checkedPaths = next, cachedEntriesByPath = cache)
        }
    }

    fun selectAllVisibleApks() {
        _fileBrowserState.update { state ->
            val q = state.searchQuery.trim().lowercase()
            val visibleApks = state.entries.filter {
                !it.isDirectory && (q.isEmpty() || it.name.lowercase().contains(q))
            }
            val next = state.checkedPaths.toMutableSet()
            val cache = state.cachedEntriesByPath.toMutableMap()
            visibleApks.forEach { entry ->
                next.add(entry.path)
                cache[entry.path] = entry
            }
            state.copy(checkedPaths = next, cachedEntriesByPath = cache)
        }
    }

    fun clearBrowserSelection() {
        _fileBrowserState.update { it.copy(checkedPaths = emptySet()) }
    }

    fun confirmBrowserSelection() {
        val state = _fileBrowserState.value
        val targetFlow = if (browserTargetTab == MainTab.RESIGN) _resignSelectedApks else _selectedApks
        val existingUriItems = targetFlow.value.filter { it.sourceType == ApkSourceType.CONTENT_URI }
        val existingByPath = targetFlow.value.associateBy { it.originalPath }

        val pickedItems = state.checkedPaths.map { path ->
            val cached = state.cachedEntriesByPath[path]
            val prev = existingByPath[path]
            if (cached != null) {
                SelectedApkItem(
                    id = path,
                    displayName = cached.name,
                    originalPath = cached.path,
                    sourceType = if (cached.viaRoot) ApkSourceType.ROOT_FILE else ApkSourceType.LOCAL_FILE,
                    sizeBytes = cached.sizeBytes,
                    lastModifiedMs = cached.lastModifiedMs
                )
            } else if (prev != null) {
                prev
            } else {
                val f = File(path)
                SelectedApkItem(
                    id = path,
                    displayName = f.name,
                    originalPath = path,
                    sourceType = if (state.useRootMode) ApkSourceType.ROOT_FILE else ApkSourceType.LOCAL_FILE,
                    sizeBytes = f.length(),
                    lastModifiedMs = f.lastModified()
                )
            }
        }

        targetFlow.value = (pickedItems + existingUriItems).distinctBy { it.id }
        _fileBrowserState.update { it.copy(isOpen = false) }
    }

    fun addSafUris(uris: List<Uri>) {
        if (uris.isEmpty()) return
        viewModelScope.launch {
            val newItems = uris.mapNotNull { fileRepo.resolveUriToSelectedItem(it) }
            val targetFlow = if (browserTargetTab == MainTab.RESIGN) _resignSelectedApks else _selectedApks
            targetFlow.update { current ->
                (current + newItems).distinctBy { it.id }
            }
            _fileBrowserState.update { it.copy(isOpen = false) }
        }
    }

    fun handleExternalCommand(
        paths: List<String>,
        uris: List<Uri>,
        autoVerify: Boolean,
        returnResult: Boolean,
        silentReturn: Boolean,
        overrideLang: AppLanguage?
    ) {
        viewModelScope.launch {
            val activeLang = overrideLang ?: language.value
            if (overrideLang != null) {
                languagePrefs.setLanguage(overrideLang)
            }

            val resolvedItems = mutableListOf<SelectedApkItem>()
            paths.forEach { rawPath ->
                val f = File(rawPath)
                val sourceType = if (f.exists() && f.canRead()) {
                    ApkSourceType.LOCAL_FILE
                } else {
                    ApkSourceType.ROOT_FILE
                }
                resolvedItems += SelectedApkItem(
                    id = rawPath,
                    displayName = f.name.ifBlank { "target.apk" },
                    originalPath = rawPath,
                    sourceType = sourceType,
                    sizeBytes = if (f.exists()) f.length() else 0L,
                    lastModifiedMs = if (f.exists()) f.lastModified() else 0L
                )
            }
            uris.forEach { uri ->
                fileRepo.resolveUriToSelectedItem(uri)?.let { resolvedItems += it }
            }

            val deduped = resolvedItems.distinctBy { it.id }
            if (deduped.isEmpty()) {
                if (returnResult) {
                    _pendingExternalResult.value = PendingExternalCommandResult(
                        reports = null,
                        errorMessage = "No APK path or URI provided",
                        silentReturn = silentReturn,
                        language = activeLang
                    )
                }
                return@launch
            }

            _selectedApks.value = deduped
            if (autoVerify) {
                runVerification(
                    targets = deduped,
                    emitExternalResult = returnResult,
                    silentReturn = silentReturn,
                    activeLang = activeLang
                )
            }
        }
    }

    fun removeSelectedApk(id: String) {
        _selectedApks.update { list -> list.filterNot { it.id == id } }
    }

    fun clearSelectedApks() {
        _selectedApks.value = emptyList()
        _verificationState.value = VerificationUiState.Idle
    }

    fun getShortcutPaths(): Map<String, String> = mapOf(
        "internal" to fileRepo.getDefaultInternalPath(),
        "downloads" to fileRepo.getDownloadsPath(),
        "system" to "/system",
        "data_app" to "/data/app"
    )

    private fun loadDirectory(path: String, useRoot: Boolean) {
        _fileBrowserState.update {
            it.copy(currentPath = path, isLoading = true, errorMessage = null)
        }
        viewModelScope.launch {
            val result = fileRepo.listDirectory(path, useRoot)
            result.fold(
                onSuccess = { list ->
                    _fileBrowserState.update { state ->
                        val cache = state.cachedEntriesByPath.toMutableMap()
                        list.filter { !it.isDirectory }.forEach { cache[it.path] = it }
                        state.copy(
                            entries = list,
                            isLoading = false,
                            errorMessage = null,
                            cachedEntriesByPath = cache
                        )
                    }
                },
                onFailure = { err ->
                    _fileBrowserState.update {
                        it.copy(
                            entries = emptyList(),
                            isLoading = false,
                            errorMessage = err.message ?: "Access denied"
                        )
                    }
                }
            )
        }
    }

    fun verifySelectedApks() {
        val targets = _selectedApks.value
        if (targets.isEmpty()) return
        viewModelScope.launch {
            runVerification(
                targets = targets,
                emitExternalResult = false,
                silentReturn = false,
                activeLang = language.value
            )
        }
    }

    private suspend fun runVerification(
        targets: List<SelectedApkItem>,
        emitExternalResult: Boolean,
        silentReturn: Boolean,
        activeLang: AppLanguage
    ) {
        val reports = mutableListOf<ApkVerificationReport>()
        val stagingDir = File(getApplication<Application>().cacheDir, "apk_staging")
        try {
            withContext(Dispatchers.IO) {
                targets.forEachIndexed { index, item ->
                    _verificationState.value = VerificationUiState.Analyzing(
                        currentIndex = index + 1,
                        totalCount = targets.size,
                        currentFileName = item.displayName
                    )
                    val sessionDir = File(stagingDir, "item_$index")
                    val (readableFile, idsigFile) = fileRepo.prepareReadableApk(item, sessionDir)
                    val report = analyzer.analyze(
                        readableApkFile = readableFile,
                        displayPath = item.originalPath,
                        fallbackName = item.displayName,
                        v4IdsigFile = idsigFile
                    )
                    reports += report
                }
            }
            _verificationState.value = VerificationUiState.Success(
                reports = reports,
                selectedReportIndex = 0
            )
            if (emitExternalResult) {
                _pendingExternalResult.value = PendingExternalCommandResult(
                    reports = reports,
                    errorMessage = null,
                    silentReturn = silentReturn,
                    language = activeLang
                )
            }
        } catch (e: Exception) {
            val msg = e.message ?: "Unexpected verification failure"
            _verificationState.value = VerificationUiState.Error(msg)
            if (emitExternalResult) {
                _pendingExternalResult.value = PendingExternalCommandResult(
                    reports = null,
                    errorMessage = msg,
                    silentReturn = silentReturn,
                    language = activeLang
                )
            }
        } finally {
            withContext(Dispatchers.IO) {
                fileRepo.clearStagingCache()
            }
        }
    }

    fun selectReportIndex(index: Int) {
        val current = _verificationState.value
        if (current is VerificationUiState.Success && index in current.reports.indices) {
            _verificationState.value = current.copy(selectedReportIndex = index)
        }
    }

    fun buildTxtExportContent(): String? {
        val current = _verificationState.value as? VerificationUiState.Success ?: return null
        return ReportFormatter.formatBatchPlainText(current.reports, language.value)
    }

    fun buildJsonExportContent(): String? {
        val current = _verificationState.value as? VerificationUiState.Success ?: return null
        return ReportFormatter.formatJson(current.reports)
    }

    // --- Re-sign & Key Updater Actions ---

    fun removeResignApk(id: String) {
        _resignSelectedApks.update { list -> list.filterNot { it.id == id } }
    }

    fun clearResignApks() {
        _resignSelectedApks.value = emptyList()
        _signingState.value = SigningUiState.Idle
    }

    fun setSelectedAospProfile(profile: AospKeyProfile) {
        _selectedAospProfile.value = profile
    }

    fun updateSigningOptions(options: SigningOptions) {
        _signingOptions.value = options
    }

    fun signWithAospKey() {
        val targets = _resignSelectedApks.value
        if (targets.isEmpty()) return
        val profile = _selectedAospProfile.value
        val options = _signingOptions.value
        viewModelScope.launch {
            try {
                val loaded = withContext(Dispatchers.IO) {
                    aospKeyProvider.getAospKey(profile)
                }
                executeReSigning(
                    targets = targets,
                    privateKey = loaded.privateKey,
                    certificates = listOf(loaded.certificate),
                    signerLabel = profile.displayName,
                    options = options
                )
            } catch (e: Exception) {
                _signingState.value = SigningUiState.Error(e.message ?: "AOSP signing failed")
            }
        }
    }

    fun openCustomKeyDialog() {
        _vaultKeys.value = keystoreManager.listKeys()
        _showCustomKeyDialog.value = true
    }

    fun dismissCustomKeyDialog() {
        _showCustomKeyDialog.value = false
    }

    fun createCustomKeyAndSign(spec: CustomKeyCreationSpec, onSavedMessage: () -> Unit) {
        val targets = _resignSelectedApks.value
        val options = _signingOptions.value
        viewModelScope.launch {
            try {
                val (_, material) = withContext(Dispatchers.IO) {
                    keystoreManager.createCustomKey(spec)
                }
                _vaultKeys.value = keystoreManager.listKeys()
                if (spec.saveToVault) onSavedMessage()
                _showCustomKeyDialog.value = false
                if (targets.isNotEmpty()) {
                    executeReSigning(
                        targets = targets,
                        privateKey = material.privateKey,
                        certificates = material.certificates,
                        signerLabel = material.displayName,
                        options = options
                    )
                }
            } catch (e: Exception) {
                _signingState.value = SigningUiState.Error(e.message ?: "Custom key creation failed")
            }
        }
    }

    fun signWithVaultKey(entry: StoredKeyEntry, password: String) {
        val targets = _resignSelectedApks.value
        if (targets.isEmpty()) return
        val options = _signingOptions.value
        viewModelScope.launch {
            try {
                val material = withContext(Dispatchers.IO) {
                    keystoreManager.loadKeyMaterial(entry, password)
                }
                _showCustomKeyDialog.value = false
                executeReSigning(
                    targets = targets,
                    privateKey = material.privateKey,
                    certificates = material.certificates,
                    signerLabel = entry.alias,
                    options = options
                )
            } catch (e: Exception) {
                _signingState.value = SigningUiState.Error(e.message ?: "Failed to unlock keystore")
            }
        }
    }

    suspend fun importKeystoreFromUri(
        uri: Uri,
        storePassword: String,
        keyPassword: String
    ): Result<StoredKeyEntry> = withContext(Dispatchers.IO) {
        runCatching {
            val bytes = getApplication<Application>().contentResolver.openInputStream(uri)?.use {
                it.readBytes()
            } ?: throw IllegalStateException("Cannot read selected keystore file")
            val entry = keystoreManager.importExternalKeystore(
                bytes = bytes,
                storePassword = storePassword,
                alias = null,
                keyPassword = keyPassword
            )
            _vaultKeys.value = keystoreManager.listKeys()
            entry
        }
    }

    suspend fun exportVaultKeystoreToUri(entry: StoredKeyEntry, uri: Uri): Boolean =
        withContext(Dispatchers.IO) {
            try {
                getApplication<Application>().contentResolver.openOutputStream(uri)?.use { out ->
                    keystoreManager.exportVaultKeystore(entry, out)
                }
                true
            } catch (_: Exception) {
                false
            }
        }

    fun deleteVaultKey(id: String) {
        viewModelScope.launch(Dispatchers.IO) {
            keystoreManager.deleteKey(id)
            _vaultKeys.value = keystoreManager.listKeys()
        }
    }

    fun prepareKeyUpdater() {
        val target = _resignSelectedApks.value.firstOrNull() ?: return
        viewModelScope.launch {
            _signingState.value = SigningUiState.AnalyzingTarget(target.displayName)
            val stagingDir = File(getApplication<Application>().cacheDir, "key_updater_staging")
            try {
                val cloneSpec = withContext(Dispatchers.IO) {
                    val sessionDir = File(stagingDir, "target")
                    val (readableFile, idsigFile) = fileRepo.prepareReadableApk(target, sessionDir)
                    val report = analyzer.analyze(
                        readableApkFile = readableFile,
                        displayPath = target.originalPath,
                        fallbackName = target.displayName,
                        v4IdsigFile = idsigFile
                    )
                    KeyCloner.buildCloneSpecFromReport(report)
                }
                _signingState.value = SigningUiState.Idle
                _keyUpdaterSpec.value = cloneSpec
            } catch (e: Exception) {
                _signingState.value = SigningUiState.Error(
                    e.message ?: "Key updater failed to inspect target APK certificate"
                )
            } finally {
                withContext(Dispatchers.IO) {
                    stagingDir.deleteRecursively()
                }
            }
        }
    }

    fun updateKeyUpdaterSpec(spec: ClonedKeySpec) {
        _keyUpdaterSpec.value = spec
    }

    fun dismissKeyUpdater() {
        _keyUpdaterSpec.value = null
    }

    fun saveClonedKeyToVaultOnly(spec: ClonedKeySpec, onSaved: (StoredKeyEntry) -> Unit) {
        viewModelScope.launch {
            try {
                val (entry, _) = withContext(Dispatchers.IO) {
                    keystoreManager.createAndSaveClonedKey(spec)
                }
                _vaultKeys.value = keystoreManager.listKeys()
                _keyUpdaterSpec.value = null
                onSaved(entry)
            } catch (e: Exception) {
                _signingState.value = SigningUiState.Error(e.message ?: "Failed to save cloned key")
            }
        }
    }

    fun generateClonedKeyAndResign(spec: ClonedKeySpec) {
        val targets = _resignSelectedApks.value
        if (targets.isEmpty()) return
        val options = SigningOptions(
            signV1 = spec.signV1,
            signV2 = spec.signV2,
            signV3 = spec.signV3,
            signV4 = spec.signV4,
            zipAlign4 = _signingOptions.value.zipAlign4
        )
        viewModelScope.launch {
            try {
                val (entry, material) = withContext(Dispatchers.IO) {
                    keystoreManager.createAndSaveClonedKey(spec)
                }
                _vaultKeys.value = keystoreManager.listKeys()
                _keyUpdaterSpec.value = null
                executeReSigning(
                    targets = targets,
                    privateKey = material.privateKey,
                    certificates = material.certificates,
                    signerLabel = "${entry.alias} (Key updater)",
                    options = options
                )
            } catch (e: Exception) {
                _signingState.value = SigningUiState.Error(e.message ?: "Key updater signing failed")
            }
        }
    }

    private suspend fun executeReSigning(
        targets: List<SelectedApkItem>,
        privateKey: java.security.PrivateKey,
        certificates: List<java.security.cert.X509Certificate>,
        signerLabel: String,
        options: SigningOptions
    ) {
        val results = mutableListOf<SignedApkResult>()
        val stagingDir = File(getApplication<Application>().cacheDir, "apk_staging")
        try {
            withContext(Dispatchers.IO) {
                targets.forEachIndexed { idx, item ->
                    _signingState.value = SigningUiState.Signing(
                        currentIndex = idx + 1,
                        totalCount = targets.size,
                        currentFileName = item.displayName
                    )
                    val sessionDir = File(stagingDir, "resign_$idx")
                    val (readableFile, _) = fileRepo.prepareReadableApk(item, sessionDir)
                    val isWritableLocal = item.sourceType == ApkSourceType.LOCAL_FILE &&
                        File(item.originalPath).parentFile?.canWrite() == true
                    val res = apkReSigner.resignApk(
                        readableInputApk = readableFile,
                        sourceDisplayPath = item.originalPath,
                        sourceDisplayName = item.displayName,
                        isSourceWritableLocal = isWritableLocal,
                        privateKey = privateKey,
                        certificates = certificates,
                        signerName = signerLabel,
                        options = options
                    )
                    results += res
                }
            }
            _signingState.value = SigningUiState.Success(results = results, signerLabel = signerLabel)
        } catch (e: Exception) {
            _signingState.value = SigningUiState.Error(e.message ?: "APK re-signing failed")
        } finally {
            withContext(Dispatchers.IO) {
                fileRepo.clearStagingCache()
            }
        }
    }

    fun inspectSignedApkReport(result: SignedApkResult) {
        _verificationState.value = VerificationUiState.Success(
            reports = listOf(result.verificationReport),
            selectedReportIndex = 0
        )
        _activeTab.value = MainTab.VERIFY
    }
}
