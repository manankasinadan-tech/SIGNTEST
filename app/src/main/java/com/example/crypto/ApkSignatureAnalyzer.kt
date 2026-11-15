package com.example.crypto

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.android.apksig.ApkVerifier
import com.android.apksig.apk.ApkUtils
import com.android.apksig.internal.apk.ApkSigningBlockUtils
import com.android.apksig.internal.apk.ContentDigestAlgorithm
import com.android.apksig.internal.apk.SignatureAlgorithm
import com.android.apksig.internal.apk.v1.V1SchemeVerifier
import com.android.apksig.internal.apk.v2.V2SchemeVerifier
import com.android.apksig.util.DataSources
import com.android.apksig.util.RunnablesExecutor
import com.example.model.ApkVerificationReport
import com.example.model.CertificateDetails
import com.example.model.SchemeVerificationDetail
import com.example.model.SignatureSchemeType
import com.example.model.SigningBlockInfo
import com.example.model.SourceStampDetails
import com.example.model.V1JarDetails
import com.example.model.V3LineageNodeDetails
import java.io.File
import java.io.RandomAccessFile
import java.security.cert.X509Certificate

class ApkSignatureAnalyzer(private val context: Context) {

    fun analyze(
        readableApkFile: File,
        displayPath: String,
        fallbackName: String,
        v4IdsigFile: File? = null
    ): ApkVerificationReport {
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()

        // 1. Package metadata via PackageManager + binary AndroidManifest fallback
        val pkgMeta = readPackageMetadata(readableApkFile, fallbackName)
        val manifestInfo = readBinaryManifestInfo(readableApkFile)

        // 2. File hashes
        val fileHashes = CryptoUtils.computeFileHashes(readableApkFile)

        // 3. Raw APK Signing Block & V1 JAR inspection
        val rawBlock = ApkSigningBlockInspector.inspectSigningBlock(readableApkFile)
        val rawV1 = ApkSigningBlockInspector.inspectV1Jar(readableApkFile)

        // 4. Companion V4 .idsig lookup
        val resolvedIdsig = v4IdsigFile?.takeIf { it.exists() && it.canRead() }
            ?: File(readableApkFile.absolutePath + ".idsig").takeIf { it.exists() && it.canRead() }
            ?: File("$displayPath.idsig").takeIf { it.exists() && it.canRead() }

        // 5. Official Google apksig platform verification (V3 / V3.1 / V4 / SourceStamp / overall)
        val builder = ApkVerifier.Builder(readableApkFile)
            .setMaxCheckedPlatformVersion(36)
        if (resolvedIdsig != null) {
            builder.setV4SignatureFile(resolvedIdsig)
        }
        val result = builder.build().verify()

        result.allErrors.forEach { errors += it.toString() }
        result.warnings.forEach { warnings += it.toString() }

        val hasV1Present = rawV1.signerFiles.isNotEmpty() || result.v1SchemeSigners.isNotEmpty()
        val hasV2Present = rawBlock.pairs.any { it.idHex == "0x7109871a" } || result.v2SchemeSigners.isNotEmpty()
        val hasV3Present = rawBlock.pairs.any { it.idHex == "0xf05368c0" } || result.v3SchemeSigners.isNotEmpty()
        val hasV31Present = rawBlock.pairs.any { it.idHex == "0x1b93ad61" } || result.v31SchemeSigners.isNotEmpty()
        val hasV4Present = resolvedIdsig != null || result.v4SchemeSigners.isNotEmpty()
        val hasSourceStampPresent = rawBlock.pairs.any { it.idHex == "0x6dff800d" || it.idHex == "0x2b09189e" } ||
            result.sourceStampInfo != null

        // 6. Independent cryptographic verification for V1 and V2 even when minSdk >= 28 (e.g. API 36)
        val independentV1 = if (hasV1Present && !result.isVerifiedUsingV1Scheme) {
            verifyV1Independently(readableApkFile)
        } else null

        val independentV2 = if (hasV2Present && !result.isVerifiedUsingV2Scheme) {
            verifyV2Independently(readableApkFile)
        } else null

        val v1Verified = result.isVerifiedUsingV1Scheme || (independentV1?.verified == true)
        val v2Verified = result.isVerifiedUsingV2Scheme || (independentV2?.verified == true)
        val v3Verified = result.isVerifiedUsingV3Scheme
        val v31Verified = result.isVerifiedUsingV31Scheme
        val v4Verified = result.isVerifiedUsingV4Scheme
        val stampVerified = result.isSourceStampVerified

        independentV1?.errors?.forEach { errors += "[V1] $it" }
        independentV1?.warnings?.forEach { warnings += "[V1] $it" }
        independentV2?.errors?.forEach { errors += "[V2] $it" }
        independentV2?.warnings?.forEach { warnings += "[V2] $it" }

        val detectedSchemes = linkedSetOf<SignatureSchemeType>()
        val verifiedSchemes = linkedSetOf<SignatureSchemeType>()

        if (hasV1Present) detectedSchemes += SignatureSchemeType.V1
        if (hasV2Present) detectedSchemes += SignatureSchemeType.V2
        if (hasV3Present) detectedSchemes += SignatureSchemeType.V3
        if (hasV31Present) detectedSchemes += SignatureSchemeType.V3_1
        if (hasV4Present) detectedSchemes += SignatureSchemeType.V4
        if (hasSourceStampPresent) detectedSchemes += SignatureSchemeType.SOURCE_STAMP

        if (v1Verified) verifiedSchemes += SignatureSchemeType.V1
        if (v2Verified) verifiedSchemes += SignatureSchemeType.V2
        if (v3Verified) verifiedSchemes += SignatureSchemeType.V3
        if (v31Verified) verifiedSchemes += SignatureSchemeType.V3_1
        if (v4Verified) verifiedSchemes += SignatureSchemeType.V4
        if (stampVerified) verifiedSchemes += SignatureSchemeType.SOURCE_STAMP

        // Collect certificates with their scheme tags
        val certSchemeMap = linkedMapOf<String, Pair<X509Certificate, MutableSet<String>>>()
        fun registerCert(cert: X509Certificate?, tag: String) {
            if (cert == null) return
            val key = CryptoUtils.digestHex(cert.encoded, "SHA-256")
            val entry = certSchemeMap.getOrPut(key) { cert to linkedSetOf() }
            entry.second += tag
        }

        result.v1SchemeSigners.forEach { signer ->
            registerCert(signer.certificate, "V1")
            signer.certificateChain.drop(1).forEach { registerCert(it, "V1-Chain") }
        }
        independentV1?.signers?.forEach { signer ->
            registerCert(signer.certChain.firstOrNull(), "V1")
            signer.certChain.drop(1).forEach { registerCert(it, "V1-Chain") }
        }
        result.v2SchemeSigners.forEach { signer ->
            registerCert(signer.certificate, "V2")
            signer.certificates.drop(1).forEach { registerCert(it, "V2-Chain") }
        }
        independentV2?.signers?.forEach { signer ->
            registerCert(signer.certs.firstOrNull(), "V2")
            signer.certs.drop(1).forEach { registerCert(it, "V2-Chain") }
        }
        result.v3SchemeSigners.forEach { signer ->
            registerCert(signer.certificate, "V3")
            signer.certificates.drop(1).forEach { registerCert(it, "V3-Chain") }
        }
        result.v31SchemeSigners.forEach { signer ->
            registerCert(signer.certificate, "V3.1")
            signer.certificates.drop(1).forEach { registerCert(it, "V3.1-Chain") }
        }
        result.v4SchemeSigners.forEach { signer ->
            registerCert(signer.certificate, "V4")
        }
        result.signerCertificates.forEach { cert ->
            registerCert(cert, "Signer")
        }
        if (certSchemeMap.isEmpty()) {
            pkgMeta.fallbackCertificates.forEach { cert ->
                registerCert(cert, "PackageManager")
            }
        }

        val certificates = certSchemeMap.values.mapIndexed { idx, (cert, tags) ->
            CryptoUtils.extractCertificateDetails(
                cert = cert,
                index = idx + 1,
                schemeTags = tags.toList()
            )
        }

        // Content digest & signature algorithms per scheme
        val v2SigAlgs = linkedSetOf<String>()
        val v2DigestAlgs = linkedSetOf<String>()
        val v3SigAlgs = linkedSetOf<String>()
        val v3DigestAlgs = linkedSetOf<String>()
        val v31SigAlgs = linkedSetOf<String>()
        val v31DigestAlgs = linkedSetOf<String>()
        val allDigestAlgs = linkedSetOf<String>()

        fun collectDigestList(
            digests: List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest>,
            sigOut: MutableSet<String>,
            digOut: MutableSet<String>
        ) {
            digests.forEach { d ->
                val alg = SignatureAlgorithm.findById(d.signatureAlgorithmId)
                if (alg != null) {
                    sigOut += alg.name
                    digOut += alg.contentDigestAlgorithm.name
                    allDigestAlgs += "${alg.name} (${alg.contentDigestAlgorithm.name})"
                } else {
                    val hex = "0x%04x".format(d.signatureAlgorithmId)
                    sigOut += hex
                    allDigestAlgs += hex
                }
            }
        }

        result.v2SchemeSigners.forEach { collectDigestList(it.contentDigests, v2SigAlgs, v2DigestAlgs) }
        independentV2?.signers?.forEach { collectDigestList(it.contentDigests, v2SigAlgs, v2DigestAlgs) }
        result.v3SchemeSigners.forEach { collectDigestList(it.contentDigests, v3SigAlgs, v3DigestAlgs) }
        result.v31SchemeSigners.forEach { collectDigestList(it.contentDigests, v31SigAlgs, v31DigestAlgs) }

        val v3MinSdk = result.v3SchemeSigners.minOfOrNull { it.minSdkVersion }
        val v3MaxSdk = result.v3SchemeSigners.maxOfOrNull { it.maxSdkVersion }
        val v31MinSdk = result.v31SchemeSigners.minOfOrNull { it.minSdkVersion }

        // Build per-scheme verification matrix
        val schemeDetails = buildList {
            if (hasV1Present) {
                val signerCount = maxOf(
                    result.v1SchemeSigners.size,
                    independentV1?.signers?.size ?: 0,
                    rawV1.signerFiles.size
                )
                add(
                    SchemeVerificationDetail(
                        scheme = SignatureSchemeType.V1,
                        isPresent = true,
                        isVerified = v1Verified,
                        signerCount = signerCount,
                        signatureAlgorithms = certificates.filter { it.schemeTags.contains("V1") }
                            .map { it.sigAlgName }.distinct(),
                        digestAlgorithms = rawV1.manifestDigestAlgs,
                        notes = "${rawV1.manifestEntryCount}/${rawV1.totalEntryCount} JAR entries"
                    )
                )
            }
            if (hasV2Present) {
                val signerCount = maxOf(
                    result.v2SchemeSigners.size,
                    independentV2?.signers?.size ?: 0
                )
                add(
                    SchemeVerificationDetail(
                        scheme = SignatureSchemeType.V2,
                        isPresent = true,
                        isVerified = v2Verified,
                        signerCount = signerCount,
                        signatureAlgorithms = v2SigAlgs.toList(),
                        digestAlgorithms = v2DigestAlgs.toList()
                    )
                )
            }
            if (hasV3Present) {
                val range = if (v3MinSdk != null && v3MaxSdk != null) {
                    val maxStr = if (v3MaxSdk == Int.MAX_VALUE) "∞" else v3MaxSdk.toString()
                    "API $v3MinSdk..$maxStr"
                } else null
                add(
                    SchemeVerificationDetail(
                        scheme = SignatureSchemeType.V3,
                        isPresent = true,
                        isVerified = v3Verified,
                        signerCount = result.v3SchemeSigners.size,
                        signatureAlgorithms = v3SigAlgs.toList(),
                        digestAlgorithms = v3DigestAlgs.toList(),
                        sdkRange = range
                    )
                )
            }
            if (hasV31Present) {
                add(
                    SchemeVerificationDetail(
                        scheme = SignatureSchemeType.V3_1,
                        isPresent = true,
                        isVerified = v31Verified,
                        signerCount = result.v31SchemeSigners.size,
                        signatureAlgorithms = v31SigAlgs.toList(),
                        digestAlgorithms = v31DigestAlgs.toList(),
                        sdkRange = v31MinSdk?.let { "API $it+" }
                    )
                )
            }
            if (hasV4Present) {
                add(
                    SchemeVerificationDetail(
                        scheme = SignatureSchemeType.V4,
                        isPresent = true,
                        isVerified = v4Verified,
                        signerCount = result.v4SchemeSigners.size,
                        signatureAlgorithms = emptyList(),
                        digestAlgorithms = emptyList(),
                        notes = resolvedIdsig?.name
                    )
                )
            }
            if (hasSourceStampPresent) {
                add(
                    SchemeVerificationDetail(
                        scheme = SignatureSchemeType.SOURCE_STAMP,
                        isPresent = true,
                        isVerified = stampVerified,
                        signerCount = if (result.sourceStampInfo?.certificate != null) 1 else 0,
                        signatureAlgorithms = result.sourceStampInfo?.certificate?.sigAlgName?.let { listOf(it) }
                            ?: emptyList(),
                        digestAlgorithms = emptyList()
                    )
                )
            }
        }

        // V3 / V3.1 Lineage
        val lineageNodes = mutableListOf<V3LineageNodeDetails>()
        val lineage = result.signingCertificateLineage
        if (lineage != null) {
            try {
                lineage.certificatesInLineage.forEachIndexed { idx, cert ->
                    val caps = try {
                        val c = lineage.getSignerCapabilities(cert)
                        buildList {
                            if (c.hasInstalledData()) add("INSTALLED_DATA")
                            if (c.hasSharedUid()) add("SHARED_UID")
                            if (c.hasPermission()) add("PERMISSION")
                            if (c.hasRollback()) add("ROLLBACK")
                            if (c.hasAuth()) add("AUTH")
                        }
                    } catch (_: Exception) {
                        emptyList()
                    }
                    lineageNodes += V3LineageNodeDetails(
                        index = idx + 1,
                        certSha256 = CryptoUtils.digestHex(cert.encoded, "SHA-256"),
                        subjectDn = cert.subjectX500Principal.name,
                        sigAlg = cert.sigAlgName ?: "Unknown",
                        flags = 0,
                        capabilities = caps
                    )
                }
            } catch (_: Exception) {
            }
        }

        // SourceStamp details
        val stampInfo = result.sourceStampInfo
        val sourceStampDetails = if (stampInfo != null || hasSourceStampPresent) {
            val stampCert = stampInfo?.certificate?.let {
                CryptoUtils.extractCertificateDetails(it, index = 1, schemeTags = listOf("SourceStamp"))
            }
            val stampDigest = stampInfo?.certificate?.let {
                CryptoUtils.digestHex(it.encoded, "SHA-256")
            }
            SourceStampDetails(
                isPresent = true,
                isVerified = stampVerified,
                stampDigestSha256 = stampDigest,
                timestampEpochSeconds = stampInfo?.timestampEpochSeconds?.takeIf { it > 0L },
                certificate = stampCert,
                errors = stampInfo?.errors?.map { it.toString() } ?: emptyList(),
                warnings = stampInfo?.warnings?.map { it.toString() } ?: emptyList()
            )
        } else null

        val v1JarDetails = if (hasV1Present) {
            V1JarDetails(
                isVerified = v1Verified,
                signerFiles = rawV1.signerFiles,
                sfFiles = rawV1.sfFiles,
                digestAlgorithms = rawV1.manifestDigestAlgs,
                signedEntryCount = rawV1.manifestEntryCount,
                totalJarEntryCount = rawV1.totalEntryCount
            )
        } else null

        val signingBlockInfo = SigningBlockInfo(
            present = rawBlock.present,
            blockOffset = rawBlock.blockOffset,
            blockSizeBytes = rawBlock.blockSizeBytes,
            pairs = rawBlock.pairs,
            v1Verified = v1Verified,
            v2Verified = v2Verified,
            v3Verified = v3Verified,
            v31Verified = v31Verified,
            v3MinSdk = v3MinSdk,
            v3MaxSdk = v3MaxSdk,
            v31RotationMinSdk = v31MinSdk,
            v4IdsigFound = resolvedIdsig != null,
            v4IdsigPath = resolvedIdsig?.absolutePath,
            v4Verified = v4Verified,
            contentDigestAlgorithms = allDigestAlgs.toList()
        )

        return ApkVerificationReport(
            id = "${displayPath}_${System.nanoTime()}",
            appLabel = pkgMeta.appLabel,
            packageName = pkgMeta.packageName ?: manifestInfo.packageName,
            versionName = pkgMeta.versionName,
            versionCode = pkgMeta.versionCode ?: manifestInfo.versionCode,
            minSdk = pkgMeta.minSdk ?: manifestInfo.minSdk,
            targetSdk = pkgMeta.targetSdk ?: manifestInfo.targetSdk,
            isDebuggable = pkgMeta.isDebuggable ?: manifestInfo.isDebuggable,
            zipEntryCount = rawV1.totalEntryCount,
            isZipAligned4 = rawBlock.isZipAligned4,
            filePath = displayPath,
            fileSizeBytes = readableApkFile.length(),
            apkSha256 = fileHashes.sha256,
            apkSha1 = fileHashes.sha1,
            apkMd5 = fileHashes.md5,
            apkCrc32Hex = fileHashes.crc32Hex,
            isVerified = result.isVerified,
            detectedSchemes = detectedSchemes.toList(),
            verifiedSchemes = verifiedSchemes.toList(),
            schemeDetails = schemeDetails,
            certificates = certificates,
            v3Lineage = lineageNodes,
            sourceStamp = sourceStampDetails,
            v1JarDetails = v1JarDetails,
            signingBlockInfo = signingBlockInfo,
            errors = errors.distinct(),
            warnings = warnings.distinct(),
            verifiedAtMs = System.currentTimeMillis()
        )
    }

    private data class IndependentV1Outcome(
        val verified: Boolean,
        val signers: List<V1SchemeVerifier.Result.SignerInfo>,
        val errors: List<String>,
        val warnings: List<String>
    )

    private data class IndependentV2Outcome(
        val verified: Boolean,
        val signers: List<ApkSigningBlockUtils.Result.SignerInfo>,
        val errors: List<String>,
        val warnings: List<String>
    )

    private fun verifyV1Independently(apkFile: File): IndependentV1Outcome? {
        return try {
            RandomAccessFile(apkFile, "r").use { raf ->
                val ds = DataSources.asDataSource(raf)
                val zipSections = ApkUtils.findZipSections(ds)
                val contentDigests = HashMap<Int, String>()
                val supportedSchemes = HashSet<Int>()
                val v1Res = V1SchemeVerifier.verify(
                    ds,
                    zipSections,
                    contentDigests,
                    supportedSchemes,
                    1,
                    23
                )
                IndependentV1Outcome(
                    verified = v1Res.verified,
                    signers = v1Res.signers,
                    errors = v1Res.errors.map { it.toString() },
                    warnings = v1Res.warnings.map { it.toString() }
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun verifyV2Independently(apkFile: File): IndependentV2Outcome? {
        return try {
            RandomAccessFile(apkFile, "r").use { raf ->
                val ds = DataSources.asDataSource(raf)
                val zipSections = ApkUtils.findZipSections(ds)
                val contentDigests = HashMap<Int, String>()
                val supportedSchemes = HashSet<Int>()
                val v2Res = V2SchemeVerifier.verify(
                    RunnablesExecutor.SINGLE_THREADED,
                    ds,
                    zipSections,
                    contentDigests,
                    supportedSchemes,
                    24,
                    27
                )
                IndependentV2Outcome(
                    verified = v2Res.verified,
                    signers = v2Res.signers,
                    errors = v2Res.errors.map { it.toString() },
                    warnings = v2Res.warnings.map { it.toString() }
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    private data class BinaryManifestInfo(
        val packageName: String? = null,
        val versionCode: Long? = null,
        val minSdk: Int? = null,
        val targetSdk: Int? = null,
        val isDebuggable: Boolean? = null
    )

    private fun readBinaryManifestInfo(apkFile: File): BinaryManifestInfo {
        return try {
            RandomAccessFile(apkFile, "r").use { raf ->
                val ds = DataSources.asDataSource(raf)
                val manifest = ApkUtils.getAndroidManifest(ds)
                val pkg = runCatching { ApkUtils.getPackageNameFromBinaryAndroidManifest(manifest) }.getOrNull()
                val vCode = runCatching { ApkUtils.getLongVersionCodeFromBinaryAndroidManifest(manifest) }.getOrNull()
                val min = runCatching { ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(manifest) }.getOrNull()
                val target = runCatching { ApkUtils.getTargetSdkVersionFromBinaryAndroidManifest(manifest) }
                    .getOrNull()?.takeIf { it > 0 }
                val debug = runCatching { ApkUtils.getDebuggableFromBinaryAndroidManifest(manifest) }.getOrNull()
                BinaryManifestInfo(pkg, vCode, min, target, debug)
            }
        } catch (_: Exception) {
            BinaryManifestInfo()
        }
    }

    private data class PackageMetadata(
        val appLabel: String,
        val packageName: String?,
        val versionName: String?,
        val versionCode: Long?,
        val minSdk: Int?,
        val targetSdk: Int?,
        val isDebuggable: Boolean?,
        val fallbackCertificates: List<X509Certificate>
    )

    @Suppress("DEPRECATION")
    private fun readPackageMetadata(apkFile: File, fallbackName: String): PackageMetadata {
        return try {
            val pm = context.packageManager
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_META_DATA
            } else {
                PackageManager.GET_SIGNATURES or PackageManager.GET_META_DATA
            }
            val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageArchiveInfo(
                    apkFile.absolutePath,
                    PackageManager.PackageInfoFlags.of(flags.toLong())
                )
            } else {
                pm.getPackageArchiveInfo(apkFile.absolutePath, flags)
            }

            if (pkgInfo == null) {
                return PackageMetadata(fallbackName, null, null, null, null, null, null, emptyList())
            }

            val appInfo = pkgInfo.applicationInfo
            val label = if (appInfo != null) {
                appInfo.sourceDir = apkFile.absolutePath
                appInfo.publicSourceDir = apkFile.absolutePath
                appInfo.loadLabel(pm).toString().takeIf { it.isNotBlank() } ?: pkgInfo.packageName
            } else {
                pkgInfo.packageName
            }

            val vCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.longVersionCode
            } else {
                pkgInfo.versionCode.toLong()
            }

            val minSdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                appInfo?.minSdkVersion
            } else null
            val targetSdk = appInfo?.targetSdkVersion
            val isDebuggable = appInfo?.let { (it.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0 }

            val fallbackCerts = mutableListOf<X509Certificate>()
            val sigBytesList = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.signingInfo?.apkContentsSigners?.map { it.toByteArray() } ?: emptyList()
            } else {
                pkgInfo.signatures?.map { it.toByteArray() } ?: emptyList()
            }
            val cf = java.security.cert.CertificateFactory.getInstance("X.509")
            sigBytesList.forEach { raw ->
                try {
                    val cert = cf.generateCertificate(raw.inputStream()) as? X509Certificate
                    if (cert != null) fallbackCerts += cert
                } catch (_: Exception) {
                }
            }

            PackageMetadata(
                appLabel = label ?: fallbackName,
                packageName = pkgInfo.packageName,
                versionName = pkgInfo.versionName,
                versionCode = vCode,
                minSdk = minSdk,
                targetSdk = targetSdk,
                isDebuggable = isDebuggable,
                fallbackCertificates = fallbackCerts
            )
        } catch (_: Exception) {
            PackageMetadata(fallbackName, null, null, null, null, null, null, emptyList())
        }
    }
}
