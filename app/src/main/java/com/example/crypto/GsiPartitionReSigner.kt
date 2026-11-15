package com.example.crypto

import android.content.Context
import com.example.data.RootShellService
import com.example.model.AospKeyProfile
import com.example.model.CertificateDetails
import com.example.model.GroupNewKeySummary
import com.example.model.PartitionAuditReport
import com.example.model.PartitionKeyStrategyMode
import com.example.model.PartitionResignPlan
import com.example.model.PartitionResignResult
import com.example.model.SignatureGroup
import com.example.model.SignatureSchemeType
import com.example.model.SigningOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Locale

class GsiPartitionReSigner(private val context: Context) {

    private data class GroupSigningMaterial(
        val group: SignatureGroup,
        val privateKey: PrivateKey,
        val certificates: List<X509Certificate>,
        val keyLabel: String,
        val newCertDetails: CertificateDetails
    )

    private val apkReSigner = ApkReSigner(context)
    private val keystoreManager = KeystoreManager(context)
    private val aospKeyProvider = AospKeyProvider(context)
    private val analyzer = GsiChainOfTrustAnalyzer(context)

    suspend fun resignPartition(
        auditReport: PartitionAuditReport,
        plan: PartitionResignPlan,
        onProgress: (phase: String, current: Int, total: Int, currentItem: String) -> Unit = { _, _, _, _ -> }
    ): Result<PartitionResignResult> = withContext(Dispatchers.IO) {
        val workRoot = File(context.cacheDir, "gsi_resign_session_${System.nanoTime()}").apply { mkdirs() }
        val errors = mutableListOf<String>()

        try {
            val totalGroups = auditReport.signatureGroups.size
            val assignmentMap = plan.groupAssignments.associateBy { it.groupId }
            val materialsByGroupId = linkedMapOf<String, GroupSigningMaterial>()

            // 1. Prepare / generate one signing key per detected SignatureGroup (preserving GSI key topology)
            auditReport.signatureGroups.forEachIndexed { idx, group ->
                onProgress("KEYS", idx + 1, maxOf(1, totalGroups), group.displayName)
                val material = prepareGroupMaterial(
                    group = group,
                    plan = plan,
                    assignment = assignmentMap[group.groupId]
                )
                materialsByGroupId[group.groupId] = material
            }

            // Build digest lookup maps from ALL old certificates in each group -> new group cert
            val oldSha256ToNewCert = mutableMapOf<String, CertificateDetails>()
            val oldSha1ToNewCert = mutableMapOf<String, CertificateDetails>()
            val oldSha512ToNewCert = mutableMapOf<String, CertificateDetails>()
            val resignedCountByGroup = mutableMapOf<String, Int>()

            auditReport.signatureGroups.forEach { group ->
                val newCert = materialsByGroupId[group.groupId]?.newCertDetails ?: return@forEach
                group.apks.flatMap { it.report.certificates }.forEach { oldCert ->
                    oldSha256ToNewCert.putIfAbsent(oldCert.sha256.lowercase(Locale.US), newCert)
                    oldSha1ToNewCert.putIfAbsent(oldCert.sha1.lowercase(Locale.US), newCert)
                    oldSha512ToNewCert.putIfAbsent(oldCert.sha512.lowercase(Locale.US), newCert)
                }
                group.primaryCert?.let { oldCert ->
                    oldSha256ToNewCert.putIfAbsent(oldCert.sha256.lowercase(Locale.US), newCert)
                    oldSha1ToNewCert.putIfAbsent(oldCert.sha1.lowercase(Locale.US), newCert)
                    oldSha512ToNewCert.putIfAbsent(oldCert.sha512.lowercase(Locale.US), newCert)
                }
            }

            // 2. Re-sign every non-symlink APK in place, preserving its detected schemes (V1/V2/V3/V4)
            var resignedApkCount = 0
            val totalApks = auditReport.apkEntries.size
            auditReport.apkEntries.forEachIndexed { idx, entry ->
                onProgress("RESIGN_APK", idx + 1, maxOf(1, totalApks), entry.relativePath)

                // Extra safety symlink check before any read or write
                val targetFile = File(entry.path)
                if (Files.isSymbolicLink(targetFile.toPath())) {
                    return@forEachIndexed
                }

                val material = materialsByGroupId[entry.groupId]
                if (material == null) {
                    errors += "Missing signing material for ${entry.relativePath}"
                    return@forEachIndexed
                }

                val schemes = entry.report.detectedSchemes
                val opts = SigningOptions(
                    signV1 = schemes.contains(SignatureSchemeType.V1) || schemes.isEmpty(),
                    signV2 = schemes.contains(SignatureSchemeType.V2) || schemes.isEmpty(),
                    signV3 = schemes.contains(SignatureSchemeType.V3),
                    signV4 = schemes.contains(SignatureSchemeType.V4) && entry.hasV4Idsig,
                    zipAlign4 = plan.zipAlign4
                )

                val itemWorkDir = File(workRoot, "apk_$idx").apply { mkdirs() }
                try {
                    val stagedInput: File = if (entry.viaRoot && !targetFile.canRead()) {
                        val copy = File(itemWorkDir, "input.apk")
                        val ok = RootShellService.copyFileViaRoot(entry.path, copy)
                        if (!ok) {
                            errors += "Root read failed for ${entry.relativePath}"
                            return@forEachIndexed
                        }
                        copy
                    } else {
                        targetFile
                    }

                    val stagedSignedApk = File(itemWorkDir, "signed.apk")
                    val stagedSignedIdsig = if (opts.signV4) File(itemWorkDir, "signed.apk.idsig") else null

                    apkReSigner.signApkToFile(
                        readableInputApk = stagedInput,
                        targetOutputApk = stagedSignedApk,
                        targetOutputIdsig = stagedSignedIdsig,
                        privateKey = material.privateKey,
                        certificates = material.certificates,
                        signerName = material.keyLabel,
                        options = opts
                    )

                    // Direct in-place replacement (NO .bak files!)
                    val replaceRes = replaceTargetFileInPlace(
                        stagedFile = stagedSignedApk,
                        targetPath = entry.path,
                        viaRoot = entry.viaRoot
                    )
                    if (replaceRes.isFailure) {
                        errors += "${entry.relativePath}: ${replaceRes.exceptionOrNull()?.message}"
                        return@forEachIndexed
                    }

                    if (opts.signV4 && stagedSignedIdsig != null && stagedSignedIdsig.exists()) {
                        val idsigTargetPath = "${entry.path}.idsig"
                        val idsigRes = replaceTargetFileInPlace(
                            stagedFile = stagedSignedIdsig,
                            targetPath = idsigTargetPath,
                            viaRoot = entry.viaRoot
                        )
                        if (idsigRes.isFailure) {
                            errors += "${entry.relativePath}.idsig: ${idsigRes.exceptionOrNull()?.message}"
                        }
                    }

                    resignedApkCount++
                    resignedCountByGroup[entry.groupId] = (resignedCountByGroup[entry.groupId] ?: 0) + 1
                } catch (e: Exception) {
                    errors += "${entry.relativePath}: ${e.message ?: "Re-sign failed"}"
                } finally {
                    itemWorkDir.deleteRecursively()
                }
            }

            // 3. Intelligently update ALL XML permission/signature files AFTER all APKs are signed
            var updatedXmlFileCount = 0
            var replacedXmlRefCount = 0
            val xmlDocsToUpdate = auditReport.xmlDocuments.filter { doc ->
                doc.references.any { ref ->
                    ref.normalizedSha256?.let { it in oldSha256ToNewCert } == true ||
                        ref.normalizedSha1?.let { it in oldSha1ToNewCert } == true ||
                        ref.normalizedSha512?.let { it in oldSha512ToNewCert } == true
                }
            }

            xmlDocsToUpdate.forEachIndexed { idx, doc ->
                onProgress("UPDATE_XML", idx + 1, maxOf(1, xmlDocsToUpdate.size), doc.relativePath)
                val targetXml = File(doc.path)
                if (Files.isSymbolicLink(targetXml.toPath())) return@forEachIndexed

                val rawBytes: ByteArray? = if (doc.viaRoot && !targetXml.canRead()) {
                    RootShellService.readFileBytesViaRoot(doc.path)
                } else {
                    if (targetXml.canRead()) targetXml.readBytes() else null
                }
                if (rawBytes == null || XmlSignatureEngine.isBinaryXml(rawBytes)) {
                    errors += "XML unreadable or binary: ${doc.relativePath}"
                    return@forEachIndexed
                }

                val rawText = rawBytes.toString(Charsets.UTF_8)
                val (updatedXmlText, replacedCount) = XmlSignatureEngine.updateXmlContent(
                    rawXml = rawText,
                    references = doc.references,
                    oldSha256ToNewCert = oldSha256ToNewCert,
                    oldSha1ToNewCert = oldSha1ToNewCert,
                    oldSha512ToNewCert = oldSha512ToNewCert
                )

                if (replacedCount > 0 && updatedXmlText != rawText) {
                    val stagedXml = File(workRoot, "updated_${idx}.xml")
                    stagedXml.writeText(updatedXmlText, Charsets.UTF_8)
                    val writeRes = replaceTargetFileInPlace(
                        stagedFile = stagedXml,
                        targetPath = doc.path,
                        viaRoot = doc.viaRoot
                    )
                    stagedXml.delete()
                    if (writeRes.isSuccess) {
                        updatedXmlFileCount++
                        replacedXmlRefCount += replacedCount
                    } else {
                        errors += "${doc.relativePath}: ${writeRes.exceptionOrNull()?.message}"
                    }
                }
            }

            // 4. Automatic post-resign coherence verification
            onProgress("VERIFY_POST", 1, 1, auditReport.rootPath)
            val postAudit = analyzer.analyze(
                rootPath = auditReport.rootPath,
                useRoot = auditReport.viaRoot
            ) { _, _, _, _ -> }.getOrElse { auditReport }

            val summaries = auditReport.signatureGroups.mapNotNull { group ->
                val mat = materialsByGroupId[group.groupId] ?: return@mapNotNull null
                GroupNewKeySummary(
                    groupDisplayName = group.displayName,
                    oldCertSha256 = group.certSha256,
                    newCertSha256 = mat.newCertDetails.sha256,
                    keyLabel = mat.keyLabel,
                    resignedCount = resignedCountByGroup[group.groupId] ?: 0
                )
            }

            Result.success(
                PartitionResignResult(
                    rootPath = auditReport.rootPath,
                    strategyMode = plan.strategyMode,
                    resignedApkCount = resignedApkCount,
                    skippedSymlinksCount = auditReport.skippedSymlinksCount,
                    updatedXmlFileCount = updatedXmlFileCount,
                    replacedXmlRefCount = replacedXmlRefCount,
                    groupKeySummaries = summaries,
                    postAuditReport = postAudit,
                    errors = errors
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            workRoot.deleteRecursively()
        }
    }

    private fun prepareGroupMaterial(
        group: SignatureGroup,
        plan: PartitionResignPlan,
        assignment: com.example.model.GroupKeyAssignment?
    ): GroupSigningMaterial {
        return when (plan.strategyMode) {
            PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP -> {
                val repReport = group.apks.firstOrNull { it.report.certificates.isNotEmpty() }?.report
                if (repReport != null) {
                    val safeRole = group.inferredRole.lowercase(Locale.US)
                        .replace(Regex("[^a-z0-9]+"), "_").trim('_').ifBlank { "grp" }
                    val cloneSpec = KeyCloner.buildCloneSpecFromReport(repReport).copy(
                        newAlias = "gsi_${safeRole}_g${group.index}"
                    )
                    val (privateKey, cert, label) = if (plan.saveClonedKeysToVault) {
                        val (entry, mat) = keystoreManager.createAndSaveClonedKey(cloneSpec)
                        Triple(mat.privateKey, mat.certificates.first(), entry.alias)
                    } else {
                        val (pk, c) = KeyCloner.generateFromCloneSpec(cloneSpec)
                        Triple(pk, c, cloneSpec.newAlias)
                    }
                    val details = CryptoUtils.extractCertificateDetails(cert, 1, emptyList())
                    GroupSigningMaterial(group, privateKey, listOf(cert), label, details)
                } else {
                    val loaded = aospKeyProvider.getAospKey(defaultProfileForRole(group.inferredRole))
                    val details = CryptoUtils.extractCertificateDetails(loaded.certificate, 1, emptyList())
                    GroupSigningMaterial(group, loaded.privateKey, listOf(loaded.certificate), loaded.profile.displayName, details)
                }
            }

            PartitionKeyStrategyMode.AOSP_BY_ROLE -> {
                val profile = assignment?.aospProfile ?: defaultProfileForRole(group.inferredRole)
                val loaded = aospKeyProvider.getAospKey(profile)
                val details = CryptoUtils.extractCertificateDetails(loaded.certificate, 1, emptyList())
                GroupSigningMaterial(group, loaded.privateKey, listOf(loaded.certificate), profile.displayName, details)
            }

            PartitionKeyStrategyMode.CUSTOM_VAULT -> {
                val customEntry = assignment?.customKeyEntry ?: keystoreManager.listKeys().firstOrNull()
                if (customEntry != null) {
                    val pwd = assignment?.customKeyPassword?.takeIf { it.isNotEmpty() }
                        ?: customEntry.defaultPasswordHint
                        ?: "signerlab"
                    val mat = keystoreManager.loadKeyMaterial(customEntry, pwd)
                    val details = CryptoUtils.extractCertificateDetails(mat.certificates.first(), 1, emptyList())
                    GroupSigningMaterial(group, mat.privateKey, mat.certificates, customEntry.alias, details)
                } else {
                    val loaded = aospKeyProvider.getAospKey(defaultProfileForRole(group.inferredRole))
                    val details = CryptoUtils.extractCertificateDetails(loaded.certificate, 1, emptyList())
                    GroupSigningMaterial(group, loaded.privateKey, listOf(loaded.certificate), loaded.profile.displayName, details)
                }
            }
        }
    }

    private suspend fun replaceTargetFileInPlace(
        stagedFile: File,
        targetPath: String,
        viaRoot: Boolean
    ): Result<Unit> {
        val targetFile = File(targetPath)
        if (Files.isSymbolicLink(targetFile.toPath())) {
            return Result.failure(IllegalStateException("Refusing to overwrite symbolic link: $targetPath"))
        }
        if (!viaRoot && (!targetFile.exists() || targetFile.canWrite())) {
            return try {
                val parent = targetFile.parentFile
                if (parent != null && parent.canWrite()) {
                    val tmpSibling = File(parent, ".tmp_signerlab_${System.nanoTime()}")
                    FileInputStream(stagedFile).use { input ->
                        FileOutputStream(tmpSibling).use { output ->
                            input.copyTo(output, bufferSize = 64 * 1024)
                        }
                    }
                    if (!tmpSibling.renameTo(targetFile)) {
                        FileInputStream(tmpSibling).use { input ->
                            FileOutputStream(targetFile, false).use { output ->
                                input.copyTo(output, bufferSize = 64 * 1024)
                            }
                        }
                        tmpSibling.delete()
                    }
                    Result.success(Unit)
                } else {
                    FileInputStream(stagedFile).use { input ->
                        FileOutputStream(targetFile, false).use { output ->
                            input.copyTo(output, bufferSize = 64 * 1024)
                        }
                    }
                    Result.success(Unit)
                }
            } catch (e: Exception) {
                if (viaRoot) {
                    RootShellService.overwriteFilePreservingMeta(stagedFile, targetPath)
                } else {
                    Result.failure(e)
                }
            }
        }
        return RootShellService.overwriteFilePreservingMeta(stagedFile, targetPath)
    }

    companion object {
        fun defaultProfileForRole(role: String): AospKeyProfile {
            return when {
                role.contains("Platform", ignoreCase = true) -> AospKeyProfile.PLATFORM
                role.contains("Shared", ignoreCase = true) -> AospKeyProfile.SHARED
                role.contains("Media", ignoreCase = true) -> AospKeyProfile.MEDIA
                else -> AospKeyProfile.TESTKEY
            }
        }
    }
}
