package com.example.data

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.OpenableColumns
import androidx.core.content.ContextCompat
import com.example.model.ApkSourceType
import com.example.model.FileEntry
import com.example.model.SelectedApkItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

class FileBrowserRepository(private val context: Context) {

    fun hasStoragePermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    fun getDefaultInternalPath(): String {
        return Environment.getExternalStorageDirectory().absolutePath
    }

    fun getDownloadsPath(): String {
        return Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).absolutePath
    }

    suspend fun listDirectory(path: String, useRoot: Boolean): Result<List<FileEntry>> =
        withContext(Dispatchers.IO) {
            if (useRoot) {
                return@withContext RootShellService.listDirectory(path)
            }

            val dir = File(path)
            if (java.nio.file.Files.isSymbolicLink(dir.toPath())) {
                return@withContext Result.failure(IllegalStateException("Symlink directory ignored: $path"))
            }
            val children = dir.listFiles()
            if (children != null) {
                val entries = children
                    .filter { it.isDirectory || it.name.endsWith(".apk", ignoreCase = true) }
                    .map { child ->
                        val isSymlink = java.nio.file.Files.isSymbolicLink(child.toPath())
                        FileEntry(
                            name = child.name,
                            path = child.absolutePath,
                            isDirectory = child.isDirectory,
                            sizeBytes = if (child.isDirectory || isSymlink) 0L else child.length(),
                            lastModifiedMs = child.lastModified(),
                            isReadable = !isSymlink && child.canRead(),
                            viaRoot = false,
                            isSymlink = isSymlink
                        )
                    }
                    .sortedWith(compareBy<FileEntry>({ !it.isDirectory }, { it.name.lowercase() }))
                Result.success(entries)
            } else {
                Result.failure(IllegalStateException("Directory not readable: $path"))
            }
        }

    suspend fun resolveUriToSelectedItem(uri: Uri): SelectedApkItem? = withContext(Dispatchers.IO) {
        var displayName = uri.lastPathSegment?.substringAfterLast('/') ?: "selected.apk"
        var size = 0L
        try {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIdx >= 0) displayName = cursor.getString(nameIdx) ?: displayName
                    if (sizeIdx >= 0) size = cursor.getLong(sizeIdx)
                }
            }
        } catch (_: Exception) {
        }

        val pathLabel = uri.path?.takeIf { it.startsWith("/storage/") } ?: uri.toString()
        SelectedApkItem(
            id = uri.toString(),
            displayName = displayName,
            originalPath = pathLabel,
            sourceType = ApkSourceType.CONTENT_URI,
            sizeBytes = size,
            lastModifiedMs = System.currentTimeMillis(),
            uriString = uri.toString()
        )
    }

    suspend fun prepareReadableApk(
        item: SelectedApkItem,
        stagingSessionDir: File
    ): Pair<File, File?> = withContext(Dispatchers.IO) {
        stagingSessionDir.mkdirs()
        when (item.sourceType) {
            ApkSourceType.LOCAL_FILE -> {
                val file = File(item.originalPath)
                if (file.exists() && file.canRead()) {
                    val idsig = File(item.originalPath + ".idsig").takeIf { it.exists() && it.canRead() }
                    return@withContext file to idsig
                }
                // Fallback to root if direct read fails
                val staged = File(stagingSessionDir, sanitizeFileName(item.displayName))
                if (RootShellService.copyFileViaRoot(item.originalPath, staged)) {
                    val idsigStaged = stageIdsigViaRoot(item.originalPath, staged)
                    return@withContext staged to idsigStaged
                }
                throw IllegalStateException("Cannot read APK file: ${item.originalPath}")
            }

            ApkSourceType.ROOT_FILE -> {
                val direct = File(item.originalPath)
                if (direct.exists() && direct.canRead()) {
                    val idsig = File(item.originalPath + ".idsig").takeIf { it.exists() && it.canRead() }
                    return@withContext direct to idsig
                }
                val staged = File(stagingSessionDir, sanitizeFileName(item.displayName))
                if (!RootShellService.copyFileViaRoot(item.originalPath, staged)) {
                    throw IllegalStateException("Root copy failed: ${item.originalPath}")
                }
                val idsigStaged = stageIdsigViaRoot(item.originalPath, staged)
                staged to idsigStaged
            }

            ApkSourceType.CONTENT_URI -> {
                val uri = Uri.parse(item.uriString ?: throw IllegalStateException("Missing URI"))
                val staged = File(stagingSessionDir, sanitizeFileName(item.displayName))
                context.contentResolver.openInputStream(uri)?.use { input ->
                    FileOutputStream(staged).use { output ->
                        input.copyTo(output, bufferSize = 64 * 1024)
                    }
                } ?: throw IllegalStateException("Cannot open URI: $uri")
                staged to null
            }
        }
    }

    private suspend fun stageIdsigViaRoot(remoteApkPath: String, stagedApk: File): File? {
        val remoteIdsig = "$remoteApkPath.idsig"
        if (!RootShellService.fileExistsViaRoot(remoteIdsig)) return null
        val stagedIdsig = File(stagedApk.absolutePath + ".idsig")
        return if (RootShellService.copyFileViaRoot(remoteIdsig, stagedIdsig)) stagedIdsig else null
    }

    fun clearStagingCache() {
        File(context.cacheDir, "apk_staging").deleteRecursively()
    }

    private fun sanitizeFileName(name: String): String {
        val clean = name.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        return if (clean.endsWith(".apk", ignoreCase = true)) clean else "$clean.apk"
    }
}
