package com.example.crypto

import android.content.Context
import android.os.Environment
import com.android.apksig.ApkSigner
import com.android.apksig.KeyConfig
import com.android.apksig.apk.ApkUtils
import com.android.apksig.util.DataSources
import com.example.model.SignatureSchemeType
import com.example.model.SignedApkResult
import com.example.model.SigningOptions
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ApkReSigner(private val context: Context) {

    private class CountingOutputStream(out: OutputStream) : FilterOutputStream(out) {
        var count: Long = 0L
            private set

        override fun write(b: Int) {
            out.write(b)
            count++
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            count += len
        }
    }

    fun resignApk(
        readableInputApk: File,
        sourceDisplayPath: String,
        sourceDisplayName: String,
        isSourceWritableLocal: Boolean,
        privateKey: PrivateKey,
        certificates: List<X509Certificate>,
        signerName: String,
        options: SigningOptions
    ): SignedApkResult {
        require(certificates.isNotEmpty()) { "At least one X.509 certificate is required" }
        require(options.signV1 || options.signV2 || options.signV3 || options.signV4) {
            "Enable at least one signature scheme (V1, V2, V3, or V4)"
        }

        val workDir = File(context.cacheDir, "resign_work_${System.nanoTime()}").apply { mkdirs() }
        try {
            val cleanedApk = File(workDir, "cleaned_aligned.apk")
            cleanAndAlignApk(
                inputApk = readableInputApk,
                outputApk = cleanedApk,
                align4 = options.zipAlign4
            )

            val outputFile = resolveOutputFile(
                sourceDisplayPath = sourceDisplayPath,
                sourceDisplayName = sourceDisplayName,
                isSourceWritableLocal = isSourceWritableLocal
            )
            outputFile.parentFile?.mkdirs()

            val tempSigned = File(workDir, "signed_temp.apk")
            val tempIdsig = File(workDir, "signed_temp.apk.idsig")

            val detectedMinSdk = readMinSdkOrDefault(cleanedApk, defaultSdk = 21)
            val signerConfig = ApkSigner.SignerConfig.Builder(
                signerName.ifBlank { "SignerLAB" },
                KeyConfig.Jca(privateKey),
                certificates
            ).build()

            val effectiveV2 = options.signV2 || options.signV4 // V4 requires V2 or V3
            val builder = ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(cleanedApk)
                .setOutputApk(tempSigned)
                .setMinSdkVersion(detectedMinSdk)
                .setV1SigningEnabled(options.signV1)
                .setV2SigningEnabled(effectiveV2)
                .setV3SigningEnabled(options.signV3)
                .setV4SigningEnabled(options.signV4)
                .setAlignFileSize(options.zipAlign4)
                .setDebuggableApkPermitted(true)
                .setOtherSignersSignaturesPreserved(false)
                .setCreatedBy("SignerLAB")

            if (options.signV4) {
                builder.setV4SignatureOutputFile(tempIdsig)
            }

            builder.build().sign()

            copyFile(tempSigned, outputFile)
            var finalIdsigPath: String? = null
            var v4FileForVerify: File? = null
            if (options.signV4 && tempIdsig.exists()) {
                val outIdsig = File(outputFile.absolutePath + ".idsig")
                copyFile(tempIdsig, outIdsig)
                finalIdsigPath = outIdsig.absolutePath
                v4FileForVerify = outIdsig
            }

            // Immediately run full verification on the newly signed APK
            val analyzer = ApkSignatureAnalyzer(context)
            val report = analyzer.analyze(
                readableApkFile = outputFile,
                displayPath = outputFile.absolutePath,
                fallbackName = outputFile.name,
                v4IdsigFile = v4FileForVerify
            )

            val appliedSchemes = buildList {
                if (options.signV1) add(SignatureSchemeType.V1)
                if (effectiveV2) add(SignatureSchemeType.V2)
                if (options.signV3) add(SignatureSchemeType.V3)
                if (options.signV4) add(SignatureSchemeType.V4)
            }

            val certSha = CryptoUtils.digestHex(certificates.first().encoded, "SHA-256")
            return SignedApkResult(
                sourceDisplayName = sourceDisplayName,
                sourcePath = sourceDisplayPath,
                outputPath = outputFile.absolutePath,
                outputSizeBytes = outputFile.length(),
                appliedSchemes = appliedSchemes,
                signerName = signerName,
                certSha256 = certSha,
                isZipAligned4 = report.isZipAligned4,
                v4IdsigPath = finalIdsigPath,
                verificationReport = report
            )
        } finally {
            workDir.deleteRecursively()
        }
    }

    internal fun cleanAndAlignApk(inputApk: File, outputApk: File, align4: Boolean) {
        val buf = ByteArray(64 * 1024)
        ZipFile(inputApk).use { zip ->
            val countingOut = CountingOutputStream(BufferedOutputStream(FileOutputStream(outputApk)))
            ZipOutputStream(countingOut).use { zos ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val src = entries.nextElement()
                    val name = src.name
                    if (isSignatureEntry(name)) continue
                    if (src.isDirectory) {
                        val dirEntry = ZipEntry(name).apply {
                            time = src.time
                            method = ZipEntry.STORED
                            size = 0L
                            compressedSize = 0L
                            crc = 0L
                        }
                        zos.putNextEntry(dirEntry)
                        zos.closeEntry()
                        zos.flush()
                        continue
                    }

                    val outEntry = ZipEntry(name).apply {
                        time = src.time
                    }

                    if (src.method == ZipEntry.STORED) {
                        outEntry.method = ZipEntry.STORED
                        val rawBytes: ByteArray? = if (src.size < 0 || src.crc < 0) {
                            zip.getInputStream(src).use { it.readBytes() }
                        } else null

                        if (rawBytes != null) {
                            val crc = CRC32().apply { update(rawBytes) }.value
                            outEntry.size = rawBytes.size.toLong()
                            outEntry.compressedSize = rawBytes.size.toLong()
                            outEntry.crc = crc
                        } else {
                            outEntry.size = src.size
                            outEntry.compressedSize = src.size
                            outEntry.crc = src.crc
                        }

                        if (align4) {
                            zos.flush()
                            val currentOffset = countingOut.count
                            val nameLen = name.toByteArray(Charsets.UTF_8).size
                            val alignBoundary = if (name.endsWith(".so", ignoreCase = true)) 4096L else 4L
                            val dataOffset = currentOffset + 30L + nameLen.toLong()
                            val padding = ((alignBoundary - (dataOffset % alignBoundary)) % alignBoundary).toInt()
                            if (padding > 0) {
                                outEntry.extra = ByteArray(padding)
                            }
                        }

                        zos.putNextEntry(outEntry)
                        if (rawBytes != null) {
                            zos.write(rawBytes)
                        } else {
                            zip.getInputStream(src).use { input ->
                                while (true) {
                                    val r = input.read(buf)
                                    if (r <= 0) break
                                    zos.write(buf, 0, r)
                                }
                            }
                        }
                        zos.closeEntry()
                        zos.flush()
                    } else {
                        outEntry.method = ZipEntry.DEFLATED
                        zos.putNextEntry(outEntry)
                        zip.getInputStream(src).use { input ->
                            while (true) {
                                val r = input.read(buf)
                                if (r <= 0) break
                                zos.write(buf, 0, r)
                            }
                        }
                        zos.closeEntry()
                        zos.flush()
                    }
                }
            }
        }
    }

    private fun isSignatureEntry(name: String): Boolean {
        val upper = name.uppercase(Locale.US)
        if (!upper.startsWith("META-INF/")) return false
        val fileName = upper.removePrefix("META-INF/")
        if (fileName.contains('/')) return false
        return fileName == "MANIFEST.MF" ||
            fileName.endsWith(".SF") ||
            fileName.endsWith(".RSA") ||
            fileName.endsWith(".DSA") ||
            fileName.endsWith(".EC") ||
            fileName.startsWith("SIG-")
    }

    private fun resolveOutputFile(
        sourceDisplayPath: String,
        sourceDisplayName: String,
        isSourceWritableLocal: Boolean
    ): File {
        val baseName = sourceDisplayName.removeSuffix(".apk").removeSuffix(".APK")
            .ifBlank { "app" }
        val signedName = if (baseName.endsWith("-signed", ignoreCase = true)) {
            "${baseName}-resigned.apk"
        } else {
            "${baseName}-signed.apk"
        }

        if (isSourceWritableLocal) {
            val srcFile = File(sourceDisplayPath)
            val parent = srcFile.parentFile
            if (parent != null && parent.exists() && parent.canWrite()) {
                return File(parent, signedName)
            }
        }

        // Default public Downloads/SignerLAB directory if writable
        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val signerLabDir = File(downloadsDir, "SignerLAB")
        if (signerLabDir.exists() || signerLabDir.mkdirs()) {
            if (signerLabDir.canWrite()) {
                return File(signerLabDir, signedName)
            }
        }

        // App-scoped fallback guaranteed writable without storage permission
        val appFallback = context.getExternalFilesDir("signed_apks") ?: File(context.filesDir, "signed_apks")
        appFallback.mkdirs()
        return File(appFallback, signedName)
    }

    private fun readMinSdkOrDefault(apkFile: File, defaultSdk: Int): Int {
        return try {
            RandomAccessFile(apkFile, "r").use { raf ->
                val ds = DataSources.asDataSource(raf)
                val manifest = ApkUtils.getAndroidManifest(ds)
                ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(manifest).coerceAtLeast(1)
            }
        } catch (_: Exception) {
            defaultSdk
        }
    }

    private fun copyFile(src: File, dst: File) {
        FileInputStream(src).use { input ->
            FileOutputStream(dst).use { output ->
                input.copyTo(output, bufferSize = 64 * 1024)
            }
        }
    }
}
