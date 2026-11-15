package com.example.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.FileVisitOption
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.util.EnumSet

object GsiPartitionScanner {

    data class ScannedApkFile(
        val path: String,
        val sizeBytes: Long,
        val viaRoot: Boolean
    )

    data class PartitionScanResult(
        val rootPath: String,
        val viaRoot: Boolean,
        val apkFiles: List<ScannedApkFile>,
        val xmlFiles: List<String>,
        val skippedSymlinks: List<String>
    )

    suspend fun scan(rootPath: String, preferRoot: Boolean): Result<PartitionScanResult> =
        withContext(Dispatchers.IO) {
            val cleanRoot = rootPath.trimEnd('/').ifEmpty { "/" }
            val rootFile = File(cleanRoot)

            if (preferRoot) {
                val rootRes = RootShellService.scanPartitionViaRoot(cleanRoot)
                if (rootRes.isSuccess) {
                    val listing = rootRes.getOrThrow()
                    return@withContext Result.success(
                        PartitionScanResult(
                            rootPath = cleanRoot,
                            viaRoot = true,
                            apkFiles = listing.apkFiles.map { (p, sz) ->
                                ScannedApkFile(path = p, sizeBytes = sz, viaRoot = true)
                            }.sortedBy { it.path },
                            xmlFiles = listing.xmlFiles.sorted(),
                            skippedSymlinks = listing.skippedSymlinks.sorted()
                        )
                    )
                }
                // Fallback to local scan only if directory is locally readable and NOT a symlink
                if (!rootFile.exists() || !rootFile.canRead()) {
                    return@withContext Result.failure(
                        rootRes.exceptionOrNull() ?: IllegalStateException("Root scan failed: $cleanRoot")
                    )
                }
            }

            try {
                val rootNioPath = rootFile.toPath()
                if (Files.isSymbolicLink(rootNioPath)) {
                    return@withContext Result.failure(
                        IllegalStateException("Refusing to scan symbolic link root: $cleanRoot")
                    )
                }
                if (!Files.exists(rootNioPath, LinkOption.NOFOLLOW_LINKS) ||
                    !Files.isDirectory(rootNioPath, LinkOption.NOFOLLOW_LINKS)
                ) {
                    return@withContext Result.failure(
                        IllegalStateException("Target directory does not exist: $cleanRoot")
                    )
                }
                if (!rootFile.canRead()) {
                    // Try root automatically if local access denied
                    val rootRes = RootShellService.scanPartitionViaRoot(cleanRoot)
                    if (rootRes.isSuccess) {
                        val listing = rootRes.getOrThrow()
                        return@withContext Result.success(
                            PartitionScanResult(
                                rootPath = cleanRoot,
                                viaRoot = true,
                                apkFiles = listing.apkFiles.map { (p, sz) ->
                                    ScannedApkFile(path = p, sizeBytes = sz, viaRoot = true)
                                }.sortedBy { it.path },
                                xmlFiles = listing.xmlFiles.sorted(),
                                skippedSymlinks = listing.skippedSymlinks.sorted()
                            )
                        )
                    }
                    return@withContext Result.failure(
                        IllegalStateException("Directory not readable (enable Storage or Root): $cleanRoot")
                    )
                }

                val canonicalRoot = rootNioPath.toRealPath(LinkOption.NOFOLLOW_LINKS)
                val apks = mutableListOf<ScannedApkFile>()
                val xmls = mutableListOf<String>()
                val symlinks = mutableListOf<String>()

                Files.walkFileTree(
                    rootNioPath,
                    EnumSet.noneOf(FileVisitOption::class.java),
                    Int.MAX_VALUE,
                    object : SimpleFileVisitor<Path>() {
                        override fun preVisitDirectory(
                            dir: Path,
                            attrs: BasicFileAttributes
                        ): FileVisitResult {
                            if (Files.isSymbolicLink(dir) || attrs.isSymbolicLink) {
                                symlinks += dir.toString()
                                return FileVisitResult.SKIP_SUBTREE
                            }
                            val real = runCatching { dir.toRealPath(LinkOption.NOFOLLOW_LINKS) }.getOrNull()
                            if (real != null && !real.startsWith(canonicalRoot)) {
                                symlinks += dir.toString()
                                return FileVisitResult.SKIP_SUBTREE
                            }
                            return FileVisitResult.CONTINUE
                        }

                        override fun visitFile(
                            file: Path,
                            attrs: BasicFileAttributes
                        ): FileVisitResult {
                            if (Files.isSymbolicLink(file) || attrs.isSymbolicLink) {
                                symlinks += file.toString()
                                return FileVisitResult.CONTINUE
                            }
                            val name = file.fileName?.toString() ?: return FileVisitResult.CONTINUE
                            when {
                                name.endsWith(".apk", ignoreCase = true) -> {
                                    apks += ScannedApkFile(
                                        path = file.toString(),
                                        sizeBytes = attrs.size(),
                                        viaRoot = false
                                    )
                                }
                                name.endsWith(".xml", ignoreCase = true) -> {
                                    xmls += file.toString()
                                }
                            }
                            return FileVisitResult.CONTINUE
                        }

                        override fun visitFileFailed(file: Path, exc: java.io.IOException?): FileVisitResult {
                            if (Files.isSymbolicLink(file)) {
                                symlinks += file.toString()
                            }
                            return FileVisitResult.CONTINUE
                        }
                    }
                )

                Result.success(
                    PartitionScanResult(
                        rootPath = cleanRoot,
                        viaRoot = false,
                        apkFiles = apks.sortedBy { it.path },
                        xmlFiles = xmls.sorted(),
                        skippedSymlinks = symlinks.sorted()
                    )
                )
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
}
