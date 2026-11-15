package com.example.api

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import com.example.crypto.ApkSignatureAnalyzer
import com.example.crypto.ReportFormatter
import com.example.data.FileBrowserRepository
import com.example.data.RootShellService
import com.example.model.ApkSourceType
import com.example.model.AppLanguage
import com.example.model.SelectedApkItem
import kotlinx.coroutines.runBlocking
import java.io.File

class SignerCommandProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val ctx = context ?: return errorBundle("Context unavailable")
        val fileRepo = FileBrowserRepository(ctx)

        return when (method) {
            SignerApiContract.METHOD_PING -> {
                Bundle().apply {
                    putString("status", "ok")
                    putString("app", "SignerLAB")
                    putString("api_version", SignerApiContract.API_VERSION)
                    putBoolean("has_storage_access", fileRepo.hasStoragePermission())
                    putBoolean("has_su_binary", RootShellService.hasSuBinary())
                }
            }

            SignerApiContract.METHOD_VERIFY_APK -> {
                val langCode = extras?.getString(SignerApiContract.EXTRA_LANG)
                val lang = if (langCode.equals("en", ignoreCase = true)) AppLanguage.EN else AppLanguage.FR

                val paths = linkedSetOf<String>()
                if (!arg.isNullOrBlank()) paths += arg
                extras?.getString(SignerApiContract.EXTRA_APK_PATH)?.takeIf { it.isNotBlank() }?.let { paths += it }
                extras?.getStringArrayList(SignerApiContract.EXTRA_APK_PATHS)?.forEach {
                    if (it.isNotBlank()) paths += it
                }

                @Suppress("DEPRECATION")
                val uriExtra: Uri? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    extras?.getParcelable(SignerApiContract.EXTRA_URI, Uri::class.java)
                } else {
                    extras?.getParcelable(SignerApiContract.EXTRA_URI)
                }

                if (paths.isEmpty() && uriExtra == null) {
                    return errorBundle("Missing apk_path, apk_paths, arg, or uri parameter")
                }

                val analyzer = ApkSignatureAnalyzer(ctx)
                val stagingDir = File(ctx.cacheDir, "api_staging_${System.nanoTime()}")

                try {
                    val items = mutableListOf<SelectedApkItem>()
                    paths.forEach { rawPath ->
                        if (rawPath.startsWith("content://")) {
                            runBlocking { fileRepo.resolveUriToSelectedItem(Uri.parse(rawPath)) }?.let {
                                items += it
                            }
                        } else {
                            val f = File(rawPath)
                            val sourceType = if (f.exists() && f.canRead()) {
                                ApkSourceType.LOCAL_FILE
                            } else {
                                ApkSourceType.ROOT_FILE
                            }
                            items += SelectedApkItem(
                                id = rawPath,
                                displayName = f.name.ifBlank { "target.apk" },
                                originalPath = rawPath,
                                sourceType = sourceType,
                                sizeBytes = if (f.exists()) f.length() else 0L,
                                lastModifiedMs = if (f.exists()) f.lastModified() else 0L
                            )
                        }
                    }

                    if (uriExtra != null) {
                        runBlocking { fileRepo.resolveUriToSelectedItem(uriExtra) }?.let { items += it }
                    }

                    if (items.isEmpty()) {
                        return errorBundle("No valid APK target resolved")
                    }

                    val reports = items.mapIndexed { idx, item ->
                        val sessionDir = File(stagingDir, "item_$idx")
                        val (readableFile, idsigFile) = runBlocking {
                            fileRepo.prepareReadableApk(item, sessionDir)
                        }
                        analyzer.analyze(
                            readableApkFile = readableFile,
                            displayPath = item.originalPath,
                            fallbackName = item.displayName,
                            v4IdsigFile = idsigFile
                        )
                    }

                    val primary = reports.first()
                    Bundle().apply {
                        putBoolean(SignerApiContract.RESULT_IS_VERIFIED, reports.all { it.isVerified })
                        putStringArrayList(
                            SignerApiContract.RESULT_DETECTED_SCHEMES,
                            ArrayList(primary.detectedSchemes.map { it.label })
                        )
                        putStringArrayList(
                            SignerApiContract.RESULT_VERIFIED_SCHEMES,
                            ArrayList(primary.verifiedSchemes.map { it.label })
                        )
                        putStringArrayList(
                            SignerApiContract.RESULT_CERT_SHA256_LIST,
                            ArrayList(primary.certificates.map { it.sha256 })
                        )
                        primary.packageName?.let { putString(SignerApiContract.RESULT_PACKAGE_NAME, it) }
                        putString(SignerApiContract.RESULT_JSON, ReportFormatter.formatJson(reports))
                        putString(
                            SignerApiContract.RESULT_TEXT,
                            ReportFormatter.formatBatchPlainText(reports, lang)
                        )
                    }
                } catch (e: Exception) {
                    errorBundle(e.message ?: "Verification failed")
                } finally {
                    stagingDir.deleteRecursively()
                }
            }

            else -> errorBundle("Unknown method: $method")
        }
    }

    private fun errorBundle(message: String): Bundle {
        return Bundle().apply {
            putBoolean(SignerApiContract.RESULT_IS_VERIFIED, false)
            putString(SignerApiContract.RESULT_ERROR, message)
        }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0
}
