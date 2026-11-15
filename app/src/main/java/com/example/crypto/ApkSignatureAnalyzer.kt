package com.example.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.android.apksig.ApkVerifier
import com.example.model.ApkVerificationReport
import com.example.model.CertificateDetails
import com.example.model.SignatureSchemeType
import com.example.model.SigningBlockInfo
import com.example.model.SourceStampDetails
import com.example.model.V1JarDetails
import com.example.model.V3LineageNodeDetails
import java.io.File
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

        // 1. Package metadata via PackageManager
        val pkgMeta = readPackageMetadata(readableApkFile, fallbackName)

        // 2. File hashes
        val (apkSha256, apkMd5, apkCrc32Hex) = CryptoUtils.computeFileHashes(readableApkFile)

        // 3. Raw APK Signing Block & V1 JAR inspection
        val rawBlock = ApkSigningBlockInspector.inspectSigningBlock(readableApkFile)
        val rawV1 = ApkSigningBlockInspector.inspectV1Jar(readableApkFile)

        // 4. Companion V4 .idsig lookup
        val resolvedIdsig = v4IdsigFile?.takeIf { it.exists() && it.canRead() }
            ?: File(readableApkFile.absolutePath + ".idsig").takeIf { it.exists() && it.canRead() }
            ?: File("$displayPath.idsig").takeIf { it.exists() && it.canRead() }

        // 5. Official Google apksig verification
        val builder = ApkVerifier.Builder(readableApkFile)
            .setMaxCheckedPlatformVersion(36)
        if (resolvedIdsig != null) {
            builder.setV4SignatureFile(resolvedIdsig)
        }

        val result = builder.build().verify()

        result.allErrors.forEach { issue ->
            errors += issue.toString()
        }
        result.warnings.forEach { issue ->
            warnings += issue.toString()
        }

        val detectedSchemes = linkedSetOf<SignatureSchemeType>()
        val verifiedSchemes = linkedSetOf<SignatureSchemeType>()

        val hasV1Present = rawV1.signerFiles.isNotEmpty() || result.v1SchemeSigners.isNotEmpty()
        val hasV2Present = rawBlock.pairs.any { it.idHex == "0x7109871a" } || result.v2SchemeSigners.isNotEmpty()
        val hasV3Present = rawBlock.pairs.any { it.idHex == "0xf05368c0" } || result.v3SchemeSigners.isNotEmpty()
        val hasV31Present = rawBlock.pairs.any { it.idHex == "0x1b93ad61" } || result.v31SchemeSigners.isNotEmpty()
        val hasV4Present = resolvedIdsig != null || result.v4SchemeSigners.isNotEmpty()
        val hasSourceStampPresent = rawBlock.pairs.any { it.idHex == "0x6dff800d" || it.idHex == "0x2b09189e" } ||
            result.sourceStampInfo != null

        if (hasV1Present) detectedSchemes += SignatureSchemeType.V1
        if (hasV2Present) detectedSchemes += SignatureSchemeType.V2
        if (hasV3Present) detectedSchemes += SignatureSchemeType.V3
        if (hasV31Present) detectedSchemes += SignatureSchemeType.V3_1
        if (hasV4Present) detectedSchemes += SignatureSchemeType.V4
        if (hasSourceStampPresent) detectedSchemes += SignatureSchemeType.SOURCE_STAMP

        if (result.isVerifiedUsingV1Scheme) verifiedSchemes += SignatureSchemeType.V1
        if (result.isVerifiedUsingV2Scheme) verifiedSchemes += SignatureSchemeType.V2
        if (result.isVerifiedUsingV3Scheme) verifiedSchemes += SignatureSchemeType.V3
        if (result.isVerifiedUsingV31Scheme) verifiedSchemes += SignatureSchemeType.V3_1
        if (result.isVerifiedUsingV4Scheme) verifiedSchemes += SignatureSchemeType.V4
        if (result.isSourceStampVerified) verifiedSchemes += SignatureSchemeType.SOURCE_STAMP

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
        result.v2SchemeSigners.forEach { signer ->
            registerCert(signer.certificate, "V2")
            signer.certificates.drop(1).forEach { registerCert(it, "V2-Chain") }
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

        // Fallback to PackageManager certificates if apksig didn't surface any (e.g. heavily malformed)
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

        // Content digest algorithms collected across V2/V3/V3.1 signers
        val digestAlgorithms = linkedSetOf<String>()
        fun recordDigest(sigAlgId: Int) {
            val alg = com.android.apksig.internal.apk.SignatureAlgorithm.findById(sigAlgId)
            digestAlgorithms += if (alg != null) {
                "${alg.name} (${alg.contentDigestAlgorithm.name})"
            } else {
                "0x%04x".format(sigAlgId)
            }
        }
        result.v2SchemeSigners.forEach { s ->
            s.contentDigests.forEach { recordDigest(it.signatureAlgorithmId) }
        }
        result.v3SchemeSigners.forEach { s ->
            s.contentDigests.forEach { recordDigest(it.signatureAlgorithmId) }
        }
        result.v31SchemeSigners.forEach { s ->
            s.contentDigests.forEach { recordDigest(it.signatureAlgorithmId) }
        }

        val v3MinSdk = result.v3SchemeSigners.minOfOrNull { it.minSdkVersion }
        val v3MaxSdk = result.v3SchemeSigners.maxOfOrNull { it.maxSdkVersion }
        val v31MinSdk = result.v31SchemeSigners.minOfOrNull { it.minSdkVersion }

        // V3 / V3.1 Lineage
        val lineageNodes = mutableListOf<V3LineageNodeDetails>()
        val lineage = result.signingCertificateLineage
        if (lineage != null) {
            try {
                val nodes = lineage.certificatesInLineage
                nodes.forEachIndexed { idx, cert ->
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
                // Keep going if lineage node enumeration differs
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
                isVerified = result.isSourceStampVerified,
                stampDigestSha256 = stampDigest,
                timestampEpochSeconds = stampInfo?.timestampEpochSeconds?.takeIf { it > 0L },
                certificate = stampCert,
                errors = stampInfo?.errors?.map { it.toString() } ?: emptyList(),
                warnings = stampInfo?.warnings?.map { it.toString() } ?: emptyList()
            )
        } else null

        val v1JarDetails = if (hasV1Present) {
            V1JarDetails(
                isVerified = result.isVerifiedUsingV1Scheme,
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
            v2Verified = result.isVerifiedUsingV2Scheme,
            v3Verified = result.isVerifiedUsingV3Scheme,
            v31Verified = result.isVerifiedUsingV31Scheme,
            v3MinSdk = v3MinSdk,
            v3MaxSdk = v3MaxSdk,
            v31RotationMinSdk = v31MinSdk,
            v4IdsigFound = resolvedIdsig != null,
            v4IdsigPath = resolvedIdsig?.absolutePath,
            v4Verified = result.isVerifiedUsingV4Scheme,
            contentDigestAlgorithms = digestAlgorithms.toList()
        )

        return ApkVerificationReport(
            id = "${displayPath}_${System.nanoTime()}",
            appLabel = pkgMeta.appLabel,
            packageName = pkgMeta.packageName,
            versionName = pkgMeta.versionName,
            versionCode = pkgMeta.versionCode,
            minSdk = pkgMeta.minSdk,
            targetSdk = pkgMeta.targetSdk,
            filePath = displayPath,
            fileSizeBytes = readableApkFile.length(),
            apkSha256 = apkSha256,
            apkMd5 = apkMd5,
            apkCrc32Hex = apkCrc32Hex,
            isVerified = result.isVerified,
            detectedSchemes = detectedSchemes.toList(),
            verifiedSchemes = verifiedSchemes.toList(),
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

    private data class PackageMetadata(
        val appLabel: String,
        val packageName: String?,
        val versionName: String?,
        val versionCode: Long?,
        val minSdk: Int?,
        val targetSdk: Int?,
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
                return PackageMetadata(fallbackName, null, null, null, null, null, emptyList())
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
                fallbackCertificates = fallbackCerts
            )
        } catch (_: Exception) {
            PackageMetadata(fallbackName, null, null, null, null, null, emptyList())
        }
    }
}
