package com.example.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.crypto.ApkSignatureAnalyzer
import com.example.crypto.ReportFormatter
import com.example.data.FileBrowserRepository
import com.example.data.LanguagePreferences
import com.example.data.RootShellService
import com.example.model.ApkSourceType
import com.example.model.AppLanguage
import com.example.model.FileEntry
import com.example.model.PermissionState
import com.example.model.RootStatus
import com.example.model.SelectedApkItem
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

class SignerViewModel(application: Application) : AndroidViewModel(application) {

    private val languagePrefs = LanguagePreferences(application)
    private val fileRepo = FileBrowserRepository(application)
    private val analyzer = ApkSignatureAnalyzer(application)

    val language: StateFlow<AppLanguage> = languagePrefs.languageFlow
        .stateIn(viewModelScope, SharingStarted.Eagerly, AppLanguage.FR)

    private val _permissionState = MutableStateFlow(
        PermissionState(
            hasStorageAccess = fileRepo.hasStoragePermission(),
            rootStatus = if (RootShellService.hasSuBinary()) RootStatus.UNKNOWN else RootStatus.UNAVAILABLE
        )
    )
    val permissionState: StateFlow<PermissionState> = _permissionState.asStateFlow()

    private val _selectedApks = MutableStateFlow<List<SelectedApkItem>>(emptyList())
    val selectedApks: StateFlow<List<SelectedApkItem>> = _selectedApks.asStateFlow()

    private val _fileBrowserState = MutableStateFlow(
        FileBrowserState(currentPath = fileRepo.getDefaultInternalPath())
    )
    val fileBrowserState: StateFlow<FileBrowserState> = _fileBrowserState.asStateFlow()

    private val _verificationState = MutableStateFlow<VerificationUiState>(VerificationUiState.Idle)
    val verificationState: StateFlow<VerificationUiState> = _verificationState.asStateFlow()

    fun setLanguage(lang: AppLanguage) {
        viewModelScope.launch {
            languagePrefs.setLanguage(lang)
        }
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

    fun openFileBrowser() {
        refreshPermissions()
        val preChecked = _selectedApks.value
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
        val existingUriItems = _selectedApks.value.filter { it.sourceType == ApkSourceType.CONTENT_URI }
        val existingByPath = _selectedApks.value.associateBy { it.originalPath }

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

        _selectedApks.value = (pickedItems + existingUriItems).distinctBy { it.id }
        _fileBrowserState.update { it.copy(isOpen = false) }
    }

    fun addSafUris(uris: List<Uri>) {
        if (uris.isEmpty()) return
        viewModelScope.launch {
            val newItems = uris.mapNotNull { fileRepo.resolveUriToSelectedItem(it) }
            _selectedApks.update { current ->
                (current + newItems).distinctBy { it.id }
            }
            _fileBrowserState.update { it.copy(isOpen = false) }
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
            val reports = mutableListOf<com.example.model.ApkVerificationReport>()
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
            } catch (e: Exception) {
                _verificationState.value = VerificationUiState.Error(
                    e.message ?: "Unexpected verification failure"
                )
            } finally {
                withContext(Dispatchers.IO) {
                    fileRepo.clearStagingCache()
                }
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
}
