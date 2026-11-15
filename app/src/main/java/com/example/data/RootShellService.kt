package com.example.data

import com.example.model.FileEntry
import com.example.model.RootStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.TimeUnit

object RootShellService {

    private val SU_CANDIDATES = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/data/adb/ksu/bin/su",
        "/data/adb/ap/bin/su"
    )

    fun hasSuBinary(): Boolean {
        if (SU_CANDIDATES.any { File(it).exists() }) return true
        return try {
            val proc = ProcessBuilder("sh", "-c", "command -v su")
                .redirectErrorStream(true)
                .start()
            proc.waitFor(2, TimeUnit.SECONDS)
            proc.inputStream.bufferedReader().readText().trim().isNotEmpty()
        } catch (_: Exception) {
            false
        }
    }

    suspend fun requestRootAccess(): Pair<RootStatus, String?> = withContext(Dispatchers.IO) {
        try {
            val process = ProcessBuilder("su", "-c", "id")
                .redirectErrorStream(true)
                .start()
            val finished = process.waitFor(8, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                return@withContext RootStatus.DENIED to null
            }
            val output = process.inputStream.bufferedReader().readText().trim()
            val exitCode = process.exitValue()
            if (exitCode == 0 && output.contains("uid=0")) {
                RootStatus.GRANTED to output
            } else if (!hasSuBinary()) {
                RootStatus.UNAVAILABLE to null
            } else {
                RootStatus.DENIED to output.takeIf { it.isNotBlank() }
            }
        } catch (_: Exception) {
            if (hasSuBinary()) RootStatus.DENIED to null else RootStatus.UNAVAILABLE to null
        }
    }

    data class PartitionScanListing(
        val apkFiles: List<Pair<String, Long>>,
        val xmlFiles: List<String>,
        val skippedSymlinks: List<String>
    )

    suspend fun listDirectory(dirPath: String): Result<List<FileEntry>> = withContext(Dispatchers.IO) {
        try {
            val escaped = shellSingleQuote(dirPath)
            // POSIX-friendly Toybox/BusyBox script printing: TYPE\tIS_SYMLINK\tSIZE\tNAME
            val script = """
                DIR=$escaped
                if [ -L "${'$'}DIR" ]; then echo "Symlink directory ignored" >&2; exit 3; fi
                if [ ! -d "${'$'}DIR" ]; then exit 2; fi
                for item in "${'$'}DIR"/* "${'$'}DIR"/.*; do
                  [ -L "${'$'}item" ] || [ -e "${'$'}item" ] || continue
                  base="${'$'}{item##*/}"
                  [ "${'$'}base" = "." ] || [ "${'$'}base" = ".." ] && continue
                  if [ -L "${'$'}item" ]; then lnk=1; else lnk=0; fi
                  if [ -d "${'$'}item" ]; then
                    printf 'D\t%s\t0\t%s\n' "${'$'}lnk" "${'$'}base"
                  else
                    case "${'$'}base" in
                      *.apk|*.APK)
                        if [ "${'$'}lnk" = "1" ]; then
                          sz=0
                        else
                          sz=$(wc -c < "${'$'}item" 2>/dev/null || echo 0)
                        fi
                        printf 'F\t%s\t%s\t%s\n' "${'$'}lnk" "${'$'}sz" "${'$'}base"
                        ;;
                    esac
                  fi
                done
            """.trimIndent()

            val proc = ProcessBuilder("su", "-c", script)
                .redirectErrorStream(true)
                .start()
            val done = proc.waitFor(15, TimeUnit.SECONDS)
            if (!done) {
                proc.destroyForcibly()
                return@withContext Result.failure(IllegalStateException("Root shell timeout"))
            }
            val output = proc.inputStream.bufferedReader().readLines()
            if (proc.exitValue() != 0) {
                return@withContext Result.failure(
                    IllegalStateException(output.joinToString("\n").ifBlank { "Root access failed" })
                )
            }

            val normalizedParent = if (dirPath == "/") "" else dirPath.trimEnd('/')
            val entries = output.mapNotNull { line ->
                val parts = line.split('\t', limit = 4)
                if (parts.size < 4) return@mapNotNull null
                val isDir = parts[0] == "D"
                val isSymlink = parts[1].trim() == "1"
                val size = parts[2].trim().toLongOrNull() ?: 0L
                val name = parts[3]
                FileEntry(
                    name = name,
                    path = "$normalizedParent/$name",
                    isDirectory = isDir,
                    sizeBytes = size,
                    lastModifiedMs = 0L,
                    isReadable = !isSymlink,
                    viaRoot = true,
                    isSymlink = isSymlink
                )
            }.sortedWith(compareBy<FileEntry>({ !it.isDirectory }, { it.name.lowercase() }))

            Result.success(entries)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun scanPartitionViaRoot(rootPath: String): Result<PartitionScanListing> = withContext(Dispatchers.IO) {
        try {
            val escaped = shellSingleQuote(rootPath)
            val script = """
                ROOT=$escaped
                if [ -L "${'$'}ROOT" ]; then echo "Target root is a symlink" >&2; exit 3; fi
                if [ ! -d "${'$'}ROOT" ]; then echo "Target root is not a directory" >&2; exit 2; fi
                find "${'$'}ROOT" -mindepth 1 -type l 2>/dev/null | while IFS= read -r p; do
                  printf 'L\t0\t%s\n' "${'$'}p"
                done
                find "${'$'}ROOT" -mindepth 1 -type f \( -name '*.apk' -o -name '*.APK' -o -name '*.xml' -o -name '*.XML' \) 2>/dev/null | while IFS= read -r p; do
                  [ -L "${'$'}p" ] && continue
                  case "${'$'}p" in
                    *.apk|*.APK)
                      sz=$(wc -c < "${'$'}p" 2>/dev/null || echo 0)
                      printf 'A\t%s\t%s\n' "${'$'}sz" "${'$'}p"
                      ;;
                    *.xml|*.XML)
                      printf 'X\t0\t%s\n' "${'$'}p"
                      ;;
                  esac
                done
            """.trimIndent()

            val proc = ProcessBuilder("su", "-c", script)
                .redirectErrorStream(true)
                .start()
            val done = proc.waitFor(90, TimeUnit.SECONDS)
            if (!done) {
                proc.destroyForcibly()
                return@withContext Result.failure(IllegalStateException("Root partition scan timeout"))
            }
            val lines = proc.inputStream.bufferedReader().readLines()
            if (proc.exitValue() != 0) {
                return@withContext Result.failure(
                    IllegalStateException(lines.joinToString("\n").ifBlank { "Root partition scan failed" })
                )
            }

            val apks = mutableListOf<Pair<String, Long>>()
            val xmls = mutableListOf<String>()
            val symlinks = mutableListOf<String>()
            lines.forEach { line ->
                val parts = line.split('\t', limit = 3)
                if (parts.size < 3) return@forEach
                val type = parts[0]
                val size = parts[1].trim().toLongOrNull() ?: 0L
                val path = parts[2]
                when (type) {
                    "A" -> apks += path to size
                    "X" -> xmls += path
                    "L" -> symlinks += path
                }
            }
            Result.success(PartitionScanListing(apks, xmls, symlinks))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun copyFileViaRoot(remotePath: String, destFile: File): Boolean = withContext(Dispatchers.IO) {
        try {
            destFile.parentFile?.mkdirs()
            val escaped = shellSingleQuote(remotePath)
            val script = "[ -L $escaped ] && exit 3; [ -f $escaped ] || exit 2; cat $escaped"
            val proc = ProcessBuilder("su", "-c", script)
                .start()
            FileOutputStream(destFile).use { out ->
                proc.inputStream.copyTo(out, bufferSize = 64 * 1024)
            }
            val done = proc.waitFor(30, TimeUnit.SECONDS)
            if (!done) {
                proc.destroyForcibly()
                return@withContext false
            }
            proc.exitValue() == 0 && destFile.exists() && destFile.length() > 0L
        } catch (_: Exception) {
            false
        }
    }

    suspend fun readFileBytesViaRoot(remotePath: String): ByteArray? = withContext(Dispatchers.IO) {
        try {
            val escaped = shellSingleQuote(remotePath)
            val script = "[ -L $escaped ] && exit 3; [ -f $escaped ] || exit 2; cat $escaped"
            val proc = ProcessBuilder("su", "-c", script).start()
            val bytes = proc.inputStream.use { it.readBytes() }
            val done = proc.waitFor(15, TimeUnit.SECONDS)
            if (!done) {
                proc.destroyForcibly()
                return@withContext null
            }
            if (proc.exitValue() == 0) bytes else null
        } catch (_: Exception) {
            null
        }
    }

    suspend fun overwriteFilePreservingMeta(srcLocalFile: File, targetRemotePath: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            try {
                if (!srcLocalFile.exists()) {
                    return@withContext Result.failure(IllegalStateException("Missing staged file: ${srcLocalFile.name}"))
                }
                val escapedTarget = shellSingleQuote(targetRemotePath)
                val escapedTemp = shellSingleQuote("${targetRemotePath}.tmp_signerlab")
                val script = """
                    TARGET=$escapedTarget
                    TMP=$escapedTemp
                    if [ -L "${'$'}TARGET" ]; then echo "Refusing to overwrite symlink: ${'$'}TARGET" >&2; exit 3; fi
                    cat > "${'$'}TMP" || { rm -f "${'$'}TMP"; echo "Write failed: ${'$'}TMP" >&2; exit 4; }
                    if [ -e "${'$'}TARGET" ]; then
                      chmod --reference="${'$'}TARGET" "${'$'}TMP" 2>/dev/null || chmod 0644 "${'$'}TMP" 2>/dev/null || true
                      chown --reference="${'$'}TARGET" "${'$'}TMP" 2>/dev/null || true
                      chcon --reference="${'$'}TARGET" "${'$'}TMP" 2>/dev/null || true
                    fi
                    mv -f "${'$'}TMP" "${'$'}TARGET" || { rm -f "${'$'}TMP"; echo "Replace failed: ${'$'}TARGET" >&2; exit 5; }
                """.trimIndent()

                val proc = ProcessBuilder("su", "-c", script)
                    .redirectErrorStream(true)
                    .start()
                srcLocalFile.inputStream().use { input ->
                    proc.outputStream.use { out ->
                        input.copyTo(out, bufferSize = 64 * 1024)
                    }
                }
                val done = proc.waitFor(45, TimeUnit.SECONDS)
                if (!done) {
                    proc.destroyForcibly()
                    return@withContext Result.failure(IllegalStateException("Root overwrite timeout for $targetRemotePath"))
                }
                val errOutput = proc.inputStream.bufferedReader().readText().trim()
                if (proc.exitValue() == 0) {
                    Result.success(Unit)
                } else {
                    Result.failure(IllegalStateException(errOutput.ifBlank { "Root overwrite failed (${proc.exitValue()})" }))
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }

    suspend fun fileExistsViaRoot(remotePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val escaped = shellSingleQuote(remotePath)
            val proc = ProcessBuilder("su", "-c", "[ ! -L $escaped ] && [ -f $escaped ] && echo YES")
                .redirectErrorStream(true)
                .start()
            proc.waitFor(4, TimeUnit.SECONDS)
            proc.inputStream.bufferedReader().readText().contains("YES")
        } catch (_: Exception) {
            false
        }
    }

    private fun shellSingleQuote(value: String): String {
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }
}
