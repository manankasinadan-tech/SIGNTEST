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

    suspend fun listDirectory(dirPath: String): Result<List<FileEntry>> = withContext(Dispatchers.IO) {
        try {
            val escaped = shellSingleQuote(dirPath)
            // POSIX-friendly Toybox/BusyBox script printing: TYPE\tSIZE\tNAME for dirs & .apk files
            val script = """
                DIR=$escaped
                if [ ! -d "${'$'}DIR" ]; then exit 2; fi
                for item in "${'$'}DIR"/* "${'$'}DIR"/.*; do
                  [ -e "${'$'}item" ] || continue
                  base="${'$'}{item##*/}"
                  [ "${'$'}base" = "." ] || [ "${'$'}base" = ".." ] && continue
                  if [ -d "${'$'}item" ]; then
                    printf 'D\t0\t%s\n' "${'$'}base"
                  else
                    case "${'$'}base" in
                      *.apk|*.APK)
                        sz=$(wc -c < "${'$'}item" 2>/dev/null || echo 0)
                        printf 'F\t%s\t%s\n' "${'$'}sz" "${'$'}base"
                        ;;
                    esac
                  fi
                done
            """.trimIndent()

            val proc = ProcessBuilder("su", "-c", script)
                .redirectErrorStream(true)
                .start()
            val done = proc.waitFor(12, TimeUnit.SECONDS)
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
                val parts = line.split('\t', limit = 3)
                if (parts.size < 3) return@mapNotNull null
                val isDir = parts[0] == "D"
                val size = parts[1].trim().toLongOrNull() ?: 0L
                val name = parts[2]
                FileEntry(
                    name = name,
                    path = "$normalizedParent/$name",
                    isDirectory = isDir,
                    sizeBytes = size,
                    lastModifiedMs = 0L,
                    isReadable = true,
                    viaRoot = true
                )
            }.sortedWith(compareBy<FileEntry>({ !it.isDirectory }, { it.name.lowercase() }))

            Result.success(entries)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun copyFileViaRoot(remotePath: String, destFile: File): Boolean = withContext(Dispatchers.IO) {
        try {
            destFile.parentFile?.mkdirs()
            val escaped = shellSingleQuote(remotePath)
            val proc = ProcessBuilder("su", "-c", "cat $escaped")
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

    suspend fun fileExistsViaRoot(remotePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val escaped = shellSingleQuote(remotePath)
            val proc = ProcessBuilder("su", "-c", "[ -f $escaped ] && echo YES")
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
