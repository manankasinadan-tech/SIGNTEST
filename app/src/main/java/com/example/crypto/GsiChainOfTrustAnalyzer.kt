package com.example.crypto

import android.content.Context
import com.example.data.GsiPartitionScanner
import com.example.data.RootShellService
import com.example.model.ApkVerificationReport
import com.example.model.PartitionApkEntry
import com.example.model.PartitionAuditReport
import com.example.model.SignatureGroup
import com.example.model.XmlSignatureDocument
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.Files
import java.util.Locale

class GsiChainOfTrustAnalyzer(private val context: Context) {

    private val apkAnalyzer = ApkSignatureAnalyzer(context)

    suspend fun analyze(
        rootPath: String,
        useRoot: Boolean,
        onProgress: (phase: String, current: Int, total: Int, currentItem: String) -> Unit = { _, _, _, _ -> }
    ): Result<PartitionAuditReport> = withContext(Dispatchers.IO) {
        try {
            onProgress("SCAN", 0, 1, rootPath)
            val scanResult = GsiPartitionScanner.scan(rootPath, useRoot).getOrElse {
                return@withContext Result.failure(it)
            }

            val totalApks = scanResult.apkFiles.size
            val apkEntries = mutableListOf<PartitionApkEntry>()
            val groupBuckets = linkedMapOf<String, MutableList<PartitionApkEntry>>()
            val stagingDir = File(context.cacheDir, "gsi_audit_staging_${System.nanoTime()}").apply { mkdirs() }

            try {
                scanResult.apkFiles.forEachIndexed { idx, scannedApk ->
                    val relPath = makeRelativePath(scanResult.rootPath, scannedApk.path)
                    onProgress("APKS", idx + 1, maxOf(1, totalApks), relPath)

                    val report: ApkVerificationReport
                    val hasIdsig: Boolean

                    if (scannedApk.viaRoot && !File(scannedApk.path).canRead()) {
                        val tempApk = File(stagingDir, "target_${idx}.apk")
                        val copied = RootShellService.copyFileViaRoot(scannedApk.path, tempApk)
                        if (!copied) {
                            throw IllegalStateException("Root copy failed for ${scannedApk.path}")
                        }
                        val remoteIdsig = "${scannedApk.path}.idsig"
                        val tempIdsig = if (RootShellService.fileExistsViaRoot(remoteIdsig)) {
                            File(tempApk.absolutePath + ".idsig").also {
                                RootShellService.copyFileViaRoot(remoteIdsig, it)
                            }
                        } else null
                        hasIdsig = tempIdsig != null && tempIdsig.exists()
                        report = apkAnalyzer.analyze(
                            readableApkFile = tempApk,
                            displayPath = scannedApk.path,
                            fallbackName = File(scannedApk.path).name,
                            v4IdsigFile = tempIdsig
                        )
                        tempApk.delete()
                        tempIdsig?.delete()
                    } else {
                        val localFile = File(scannedApk.path)
                        if (Files.isSymbolicLink(localFile.toPath())) {
                            return@forEachIndexed
                        }
                        val localIdsig = File("${scannedApk.path}.idsig").takeIf {
                            it.exists() && it.canRead() && !Files.isSymbolicLink(it.toPath())
                        }
                        hasIdsig = localIdsig != null
                        report = apkAnalyzer.analyze(
                            readableApkFile = localFile,
                            displayPath = scannedApk.path,
                            fallbackName = localFile.name,
                            v4IdsigFile = localIdsig
                        )
                    }

                    val primaryCert = report.certificates.firstOrNull()
                    val groupId = primaryCert?.sha256?.let { "cert_$it" } ?: "unsigned_${idx}"
                    val schemeSummary = report.detectedSchemes.joinToString("+") { it.label }.ifBlank { "NONE" }
                    val zone = inferPartitionZone(relPath)

                    val entry = PartitionApkEntry(
                        path = scannedApk.path,
                        relativePath = relPath,
                        partitionZone = zone,
                        viaRoot = scannedApk.viaRoot,
                        fileSizeBytes = scannedApk.sizeBytes,
                        report = report,
                        groupId = groupId,
                        schemeSummary = schemeSummary,
                        hasV4Idsig = hasIdsig
                    )
                    apkEntries += entry
                    groupBuckets.getOrPut(groupId) { mutableListOf() }.add(entry)
                }
            } finally {
                stagingDir.deleteRecursively()
            }

            // Build lookup sets of all APK certificates for intelligent XML matching
            val allCerts = apkEntries.flatMap { it.report.certificates }
            val knownSha256 = allCerts.map { it.sha256.lowercase(Locale.US) }.toSet()
            val knownSha1 = allCerts.map { it.sha1.lowercase(Locale.US) }.toSet()
            val knownSha512 = allCerts.map { it.sha512.lowercase(Locale.US) }.toSet()

            // Map digest -> groupId
            val sha256ToGroupId = mutableMapOf<String, String>()
            val sha1ToGroupId = mutableMapOf<String, String>()
            val sha512ToGroupId = mutableMapOf<String, String>()
            apkEntries.forEach { entry ->
                entry.report.certificates.forEach { cert ->
                    sha256ToGroupId.putIfAbsent(cert.sha256.lowercase(Locale.US), entry.groupId)
                    sha1ToGroupId.putIfAbsent(cert.sha1.lowercase(Locale.US), entry.groupId)
                    sha512ToGroupId.putIfAbsent(cert.sha512.lowercase(Locale.US), entry.groupId)
                }
            }

            // Scan ALL XML files cleanly
            val totalXml = scanResult.xmlFiles.size
            val parsedXmlDocs = mutableListOf<XmlSignatureDocument>()
            scanResult.xmlFiles.forEachIndexed { idx, xmlPath ->
                val relPath = makeRelativePath(scanResult.rootPath, xmlPath)
                onProgress("XML", idx + 1, maxOf(1, totalXml), relPath)

                val xmlBytes: ByteArray? = if (scanResult.viaRoot && !File(xmlPath).canRead()) {
                    RootShellService.readFileBytesViaRoot(xmlPath)
                } else {
                    val f = File(xmlPath)
                    if (Files.isSymbolicLink(f.toPath()) || !f.canRead()) null else f.readBytes()
                }
                if (xmlBytes == null || xmlBytes.isEmpty() || XmlSignatureEngine.isBinaryXml(xmlBytes)) {
                    return@forEachIndexed
                }
                val rawText = xmlBytes.toString(Charsets.UTF_8)
                val doc = XmlSignatureEngine.parseXmlDocument(
                    path = xmlPath,
                    relativePath = relPath,
                    rawText = rawText,
                    viaRoot = scanResult.viaRoot,
                    knownSha256 = knownSha256,
                    knownSha1 = knownSha1,
                    knownSha512 = knownSha512
                )
                if (doc != null) {
                    parsedXmlDocs += doc
                }
            }

            // Preliminary group metadata for labeling XML cross-links
            val sortedBuckets = groupBuckets.entries.sortedWith(
                compareByDescending<Map.Entry<String, MutableList<PartitionApkEntry>>> { it.value.size }
                    .thenBy { it.key }
            )

            // Collect seinfo & xml paths per group
            val seinfoPerGroup = mutableMapOf<String, MutableSet<String>>()
            val xmlPathsPerGroup = mutableMapOf<String, MutableSet<String>>()

            parsedXmlDocs.forEach { doc ->
                doc.references.forEach { ref ->
                    val gid = ref.normalizedSha256?.let { sha256ToGroupId[it] }
                        ?: ref.normalizedSha1?.let { sha1ToGroupId[it] }
                        ?: ref.normalizedSha512?.let { sha512ToGroupId[it] }
                    if (gid != null) {
                        xmlPathsPerGroup.getOrPut(gid) { linkedSetOf() }.add(doc.relativePath)
                        ref.seinfo?.takeIf { it.isNotBlank() }?.let { s ->
                            seinfoPerGroup.getOrPut(gid) { linkedSetOf() }.add(s)
                        }
                    }
                }
            }

            val groupDisplayNames = mutableMapOf<String, String>()
            val groupRoles = mutableMapOf<String, String>()
            sortedBuckets.forEachIndexed { idx, (gid, members) ->
                val primaryCert = members.firstOrNull()?.report?.certificates?.firstOrNull()
                val seinfoSet = seinfoPerGroup[gid].orEmpty()
                val role = inferGroupRole(
                    subjectDn = primaryCert?.subjectDn ?: "",
                    knownHint = primaryCert?.knownSignerHint,
                    seinfoValues = seinfoSet,
                    members = members
                )
                val shortSubject = extractCnOrOrg(primaryCert?.subjectDn) ?: "Unsigned"
                val displayName = "Groupe #${idx + 1} · $role ($shortSubject)"
                groupDisplayNames[gid] = displayName
                groupRoles[gid] = role
            }

            // Enrich XML references with matchedGroupId and matchedGroupLabel
            var unmatchedRefs = 0
            val linkedXmlDocs = parsedXmlDocs.map { doc ->
                val updatedRefs = doc.references.map { ref ->
                    val gid = ref.normalizedSha256?.let { sha256ToGroupId[it] }
                        ?: ref.normalizedSha1?.let { sha1ToGroupId[it] }
                        ?: ref.normalizedSha512?.let { sha512ToGroupId[it] }
                    if (gid == null) {
                        unmatchedRefs++
                        ref
                    } else {
                        ref.copy(
                            matchedGroupId = gid,
                            matchedGroupLabel = groupDisplayNames[gid]
                        )
                    }
                }
                doc.copy(references = updatedRefs)
            }

            val signatureGroups = sortedBuckets.mapIndexed { idx, (gid, members) ->
                val primaryCert = members.firstOrNull()?.report?.certificates?.firstOrNull()
                val schemes = members.flatMap { it.report.detectedSchemes }.distinct()
                SignatureGroup(
                    groupId = gid,
                    index = idx + 1,
                    displayName = groupDisplayNames[gid] ?: "Groupe #${idx + 1}",
                    inferredRole = groupRoles[gid] ?: "App / Release",
                    certSha256 = primaryCert?.sha256 ?: "UNSIGNED",
                    subjectDn = primaryCert?.subjectDn ?: "N/A",
                    primaryCert = primaryCert,
                    apks = members.sortedBy { it.relativePath },
                    matchedXmlPaths = xmlPathsPerGroup[gid]?.toList()?.sorted() ?: emptyList(),
                    seinfoValues = seinfoPerGroup[gid]?.toList()?.sorted() ?: emptyList(),
                    schemesUsed = schemes
                )
            }

            val verifiedCount = apkEntries.count { it.report.isVerified }
            val unsignedCount = apkEntries.count { it.report.certificates.isEmpty() }
            val isCoherent = apkEntries.isNotEmpty() && verifiedCount == apkEntries.size && unsignedCount == 0

            val notes = buildList {
                add("$verifiedCount / ${apkEntries.size} APK valides regroupés en ${signatureGroups.size} groupe(s) de signature.")
                if (unsignedCount > 0) {
                    add("$unsignedCount APK sans certificat X.509 détecté.")
                }
                if (linkedXmlDocs.isNotEmpty()) {
                    val totalRefs = linkedXmlDocs.sumOf { it.references.size }
                    val matchedRefs = totalRefs - unmatchedRefs
                    add("${linkedXmlDocs.size} XML de signature/permission détectés ($matchedRefs/$totalRefs empreintes liées aux APK du dossier).")
                } else {
                    add("Aucun fichier XML contenant des empreintes de signature dans ce dossier.")
                }
                if (scanResult.skippedSymlinks.isNotEmpty()) {
                    add("${scanResult.skippedSymlinks.size} lien(s) symbolique(s) strictement ignorés (protection du système hôte).")
                }
                if (unmatchedRefs > 0) {
                    add("$unmatchedRefs référence(s) XML pointent vers des clés d'autres partitions ou externes au dossier analysé.")
                }
            }

            Result.success(
                PartitionAuditReport(
                    rootPath = scanResult.rootPath,
                    viaRoot = scanResult.viaRoot,
                    totalApks = apkEntries.size,
                    verifiedApks = verifiedCount,
                    skippedSymlinksCount = scanResult.skippedSymlinks.size,
                    skippedSymlinkSamples = scanResult.skippedSymlinks.take(25),
                    totalXmlScanned = scanResult.xmlFiles.size,
                    xmlWithSignaturesCount = linkedXmlDocs.size,
                    signatureGroups = signatureGroups,
                    apkEntries = apkEntries.sortedBy { it.relativePath },
                    xmlDocuments = linkedXmlDocs.sortedBy { it.relativePath },
                    unmatchedXmlRefCount = unmatchedRefs,
                    isCoherent = isCoherent,
                    coherenceNotes = notes,
                    auditedAtMs = System.currentTimeMillis()
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun makeRelativePath(root: String, fullPath: String): String {
        val normRoot = root.trimEnd('/')
        return if (fullPath.startsWith("$normRoot/")) {
            fullPath.removePrefix("$normRoot/")
        } else {
            fullPath
        }
    }

    private fun inferPartitionZone(relativePath: String): String {
        val parts = relativePath.split('/').filter { it.isNotBlank() }
        return when {
            parts.size >= 2 -> parts.take(2).joinToString("/")
            parts.size == 1 -> parts.first()
            else -> "/"
        }
    }

    private fun inferGroupRole(
        subjectDn: String,
        knownHint: String?,
        seinfoValues: Set<String>,
        members: List<PartitionApkEntry>
    ): String {
        val lowerSeinfo = seinfoValues.map { it.lowercase(Locale.US) }
        val lowerDn = subjectDn.lowercase(Locale.US)
        val pkgNames = members.mapNotNull { it.report.packageName?.lowercase(Locale.US) }
        val paths = members.map { it.relativePath.lowercase(Locale.US) }

        return when {
            lowerSeinfo.any { it.contains("platform") } ||
                pkgNames.any { it == "android" || it == "com.android.systemui" || it == "com.android.settings" } -> "Platform"
            lowerSeinfo.any { it.contains("shared") } ||
                pkgNames.any { it.contains("contacts") || it.contains("providers.downloads") } -> "Shared"
            lowerSeinfo.any { it.contains("media") } ||
                pkgNames.any { it.contains("mediaprovider") || it.contains("gallery") } -> "Media"
            lowerSeinfo.any { it.contains("network") } ||
                pkgNames.any { it.contains("networkstack") || it.contains("tethering") } -> "NetworkStack"
            knownHint?.contains("TestKey", ignoreCase = true) == true || lowerDn.contains("android@android.com") -> "TestKey"
            lowerDn.contains("samsung") || paths.any { it.contains("vendor/") || it.contains("odm/") } -> "OEM / Vendor"
            else -> "App / Release"
        }
    }

    private fun extractCnOrOrg(dn: String?): String? {
        if (dn.isNullOrBlank()) return null
        val rdns = KeyCloner.parseRfc2253Rdns(dn)
        val cn = rdns.firstOrNull { it.key.equals("CN", ignoreCase = true) }?.value
        val org = rdns.firstOrNull { it.key.equals("O", ignoreCase = true) }?.value
        return (cn?.takeIf { it.isNotBlank() } ?: org?.takeIf { it.isNotBlank() })?.take(28)
    }
}
