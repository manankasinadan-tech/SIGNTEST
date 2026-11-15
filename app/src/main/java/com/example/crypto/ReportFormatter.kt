package com.example.crypto

import com.example.model.ApkVerificationReport
import com.example.model.AppLanguage
import com.example.model.CertificateDetails
import com.example.model.ValidityStatus
import com.example.ui.stringsFor
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.Locale

object ReportFormatter {

    fun formatDate(millis: Long, lang: AppLanguage): String {
        val locale = if (lang == AppLanguage.FR) Locale.FRENCH else Locale.ENGLISH
        return DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(millis))
    }

    fun formatPlainText(report: ApkVerificationReport, lang: AppLanguage): String {
        val s = stringsFor(lang)
        val sb = StringBuilder()

        val versionText = buildString {
            if (!report.versionName.isNullOrBlank()) {
                append(" v").append(report.versionName.removePrefix("v"))
            }
            if (report.versionCode != null) {
                append(" (").append(report.versionCode).append(")")
            }
        }
        sb.appendLine("${s.reportHeaderVerification}: ${report.appLabel}$versionText")
        sb.appendLine("${s.reportPath}: ${report.filePath}")
        if (!report.packageName.isNullOrBlank()) {
            sb.appendLine("${s.labelPackage}: ${report.packageName}")
        }
        if (report.minSdk != null || report.targetSdk != null) {
            sb.appendLine("${s.labelSdk}: min ${report.minSdk ?: "-"} / target ${report.targetSdk ?: "-"}")
        }
        report.isDebuggable?.let {
            sb.appendLine("${s.labelDebuggable}: $it")
        }
        sb.appendLine("${s.labelZipInfo}: ${report.zipEntryCount} entries | 4-byte aligned: ${report.isZipAligned4}")
        sb.appendLine()

        val schemeString = if (report.detectedSchemes.isEmpty()) {
            s.reportNone
        } else {
            report.detectedSchemes.joinToString(" + ") { it.label }
        }
        sb.appendLine("${s.reportScheme} : $schemeString")
        val statusText = when {
            !report.isVerified -> s.statusFailed
            report.warnings.isNotEmpty() -> s.statusWithWarnings
            else -> s.statusVerified
        }
        val statusLabel = if (lang == AppLanguage.FR) "Statut" else "Status"
        sb.appendLine("$statusLabel : $statusText")
        sb.appendLine("${s.labelApkSha256} : ${report.apkSha256}")
        sb.appendLine("${s.labelApkSha1} : ${report.apkSha1}")
        sb.appendLine("${s.labelApkMd5} : ${report.apkMd5}")
        sb.appendLine("${s.labelApkCrc32} : ${report.apkCrc32Hex}")
        sb.appendLine()

        if (report.schemeDetails.isNotEmpty()) {
            sb.appendLine("=== ${s.sectionSchemeMatrix} ===")
            report.schemeDetails.forEach { d ->
                val badge = if (d.isVerified) "VALID" else "FAILED"
                val extra = buildList {
                    add("signers=${d.signerCount}")
                    d.sdkRange?.let { add(it) }
                    if (d.signatureAlgorithms.isNotEmpty()) add("sig=${d.signatureAlgorithms.joinToString("/")}")
                    if (d.digestAlgorithms.isNotEmpty()) add("digest=${d.digestAlgorithms.joinToString("/")}")
                    d.notes?.let { add(it) }
                }.joinToString(", ")
                sb.appendLine("- ${d.scheme.label}: $badge ($extra)")
            }
            sb.appendLine()
        }

        report.certificates.forEach { cert ->
            appendCertificateBlock(sb, cert, lang)
            sb.appendLine()
        }

        if (report.v3Lineage.isNotEmpty()) {
            sb.appendLine("=== ${s.sectionLineageV3} ===")
            report.v3Lineage.forEach { node ->
                sb.appendLine("#${node.index} ${node.subjectDn}")
                sb.appendLine("  SHA-256: ${node.certSha256}")
                sb.appendLine("  Alg: ${node.sigAlg}")
                if (node.capabilities.isNotEmpty()) {
                    sb.appendLine("  Capabilities: ${node.capabilities.joinToString(", ")}")
                }
            }
            sb.appendLine()
        }

        report.sourceStamp?.let { stamp ->
            sb.appendLine("=== ${s.sectionSourceStamp} ===")
            sb.appendLine("Verified: ${stamp.isVerified}")
            stamp.stampDigestSha256?.let { sb.appendLine("Stamp Cert SHA-256: $it") }
            stamp.timestampEpochSeconds?.let { sb.appendLine("Timestamp: $it") }
            stamp.certificate?.let { appendCertificateBlock(sb, it, lang) }
            sb.appendLine()
        }

        report.v1JarDetails?.let { v1 ->
            sb.appendLine("=== ${s.sectionV1Jar} ===")
            sb.appendLine("Verified: ${v1.isVerified}")
            sb.appendLine("Signers: ${v1.signerFiles.joinToString(", ").ifEmpty { "-" }}")
            sb.appendLine("SF files: ${v1.sfFiles.joinToString(", ").ifEmpty { "-" }}")
            sb.appendLine("Digest algorithms: ${v1.digestAlgorithms.joinToString(", ").ifEmpty { "-" }}")
            sb.appendLine("Entries: ${v1.signedEntryCount}/${v1.totalJarEntryCount}")
            sb.appendLine()
        }

        if (report.signingBlockInfo.present) {
            sb.appendLine("=== ${s.sectionSigningBlock} ===")
            sb.appendLine(
                "Offset: 0x${report.signingBlockInfo.blockOffset.toString(16)} (${report.signingBlockInfo.blockSizeBytes} bytes)"
            )
            report.signingBlockInfo.pairs.forEach { pair ->
                sb.appendLine("  - ${pair.idHex}: ${pair.name} (${pair.sizeBytes} bytes)")
            }
            if (report.signingBlockInfo.contentDigestAlgorithms.isNotEmpty()) {
                sb.appendLine(
                    "Content Digests: ${report.signingBlockInfo.contentDigestAlgorithms.joinToString(", ")}"
                )
            }
            if (report.signingBlockInfo.v4IdsigFound) {
                sb.appendLine("V4 .idsig: ${report.signingBlockInfo.v4IdsigPath} (verified=${report.signingBlockInfo.v4Verified})")
            }
            sb.appendLine()
        }

        if (report.errors.isNotEmpty() || report.warnings.isNotEmpty()) {
            sb.appendLine("=== ${s.sectionDiagnostics} ===")
            report.errors.forEach { sb.appendLine("[ERROR] $it") }
            report.warnings.forEach { sb.appendLine("[WARN] $it") }
        }

        return sb.toString().trimEnd()
    }

    private fun appendCertificateBlock(
        sb: StringBuilder,
        cert: CertificateDetails,
        lang: AppLanguage
    ) {
        val s = stringsFor(lang)
        val schemesSuffix = if (cert.schemeTags.isNotEmpty()) {
            " [${cert.schemeTags.joinToString(", ")}]"
        } else ""
        sb.appendLine("${s.reportCertificateTitle(cert.index)}$schemesSuffix")
        cert.knownSignerHint?.let { sb.appendLine("${s.labelKnownSigner} : $it") }
        sb.appendLine("${s.reportCertType} : ${cert.type}")
        sb.appendLine("${s.reportCertVersion} : ${cert.version}")
        sb.appendLine("${s.reportSerial}: ${cert.serialNumberDecimal} (${cert.serialNumberHex})")
        sb.appendLine("${s.reportOwner} : ${cert.subjectDn}")
        val issuerText = if (cert.isSelfSigned) s.reportSelfSigned else cert.issuerDn
        sb.appendLine("${s.reportIssuer} : $issuerText")
        val fromDate = formatDate(cert.notBeforeMs, lang)
        val toDate = formatDate(cert.notAfterMs, lang)
        val validitySuffix = when (cert.validityStatus) {
            ValidityStatus.VALID -> " (${cert.daysRemaining}d)"
            ValidityStatus.EXPIRED -> " [${s.reportValidityExpired}]"
            ValidityStatus.NOT_YET_VALID -> " [${s.reportValidityNotYet}]"
        }
        sb.appendLine("${s.reportValidity} : ${s.reportValidityRange(fromDate, toDate)}$validitySuffix")
        sb.appendLine("${s.reportSigAlg} : ${cert.sigAlgName} (${cert.sigAlgOid})")
        sb.appendLine()
        sb.appendLine("${s.reportHashCode} : ${cert.hashCodeHex} (${cert.hashCodeInt})")
        sb.appendLine("${s.reportCrc32} : ${cert.crc32Hex} (${cert.crc32Long})")
        sb.appendLine("${s.reportMd5} : ${cert.md5}")
        sb.appendLine("${s.reportSha1} : ${cert.sha1}")
        sb.appendLine("${s.labelSha1Colon} : ${cert.sha1Colon}")
        sb.appendLine("${s.reportSha224} : ${cert.sha224}")
        sb.appendLine("${s.reportSha256} : ${cert.sha256}")
        sb.appendLine("${s.labelSha256Colon} : ${cert.sha256Colon}")
        sb.appendLine("${s.reportSha384} : ${cert.sha384}")
        sb.appendLine("${s.reportSha512} : ${cert.sha512}")
        sb.appendLine()
        if (cert.keyUsage.isNotEmpty()) {
            sb.appendLine("${s.labelKeyUsage} : ${cert.keyUsage.joinToString(", ")}")
        }
        if (cert.extendedKeyUsage.isNotEmpty()) {
            sb.appendLine("${s.labelExtendedKeyUsage} : ${cert.extendedKeyUsage.joinToString(", ")}")
        }
        cert.basicConstraints?.let { sb.appendLine("${s.labelBasicConstraints} : $it") }
        cert.subjectKeyIdentifier?.let { sb.appendLine("${s.labelSki} : $it") }
        cert.authorityKeyIdentifier?.let { sb.appendLine("${s.labelAki} : $it") }
        sb.appendLine()
        sb.appendLine("${s.reportCertBase64} : ${cert.certBase64}")
        sb.appendLine()
        sb.appendLine("${s.reportSigBits} : ${cert.signatureBitsHex}")
        sb.appendLine()
        sb.appendLine("${s.reportPublicKey} : ${cert.publicKeySummary}")
        sb.appendLine("${s.labelSpkiSha256} : ${cert.publicKeySpkiSha256}")
        sb.appendLine()
        sb.appendLine("${s.reportSigBase64} : ${cert.signatureBase64}")
    }

    fun formatBatchPlainText(reports: List<ApkVerificationReport>, lang: AppLanguage): String {
        return reports.joinToString("\n\n" + "=".repeat(60) + "\n\n") {
            formatPlainText(it, lang)
        }
    }

    fun formatJson(reports: List<ApkVerificationReport>): String {
        val root = JSONObject()
        root.put("tool", "SignerLAB")
        root.put("apiVersion", "1.0")
        root.put("count", reports.size)
        val arr = JSONArray()
        reports.forEach { r ->
            arr.put(reportToJson(r))
        }
        root.put("reports", arr)
        return root.toString(2)
    }

    private fun reportToJson(r: ApkVerificationReport): JSONObject {
        return JSONObject().apply {
            put("appLabel", r.appLabel)
            put("packageName", r.packageName ?: JSONObject.NULL)
            put("versionName", r.versionName ?: JSONObject.NULL)
            put("versionCode", r.versionCode ?: JSONObject.NULL)
            put("minSdk", r.minSdk ?: JSONObject.NULL)
            put("targetSdk", r.targetSdk ?: JSONObject.NULL)
            put("isDebuggable", r.isDebuggable ?: JSONObject.NULL)
            put("zipEntryCount", r.zipEntryCount)
            put("isZipAligned4", r.isZipAligned4)
            put("filePath", r.filePath)
            put("fileSizeBytes", r.fileSizeBytes)
            put("isVerified", r.isVerified)
            put("apkHashes", JSONObject().apply {
                put("sha256", r.apkSha256)
                put("sha1", r.apkSha1)
                put("md5", r.apkMd5)
                put("crc32", r.apkCrc32Hex)
            })
            put("detectedSchemes", JSONArray(r.detectedSchemes.map { it.label }))
            put("verifiedSchemes", JSONArray(r.verifiedSchemes.map { it.label }))
            put("schemeMatrix", JSONArray().apply {
                r.schemeDetails.forEach { d ->
                    put(JSONObject().apply {
                        put("scheme", d.scheme.label)
                        put("present", d.isPresent)
                        put("verified", d.isVerified)
                        put("signerCount", d.signerCount)
                        put("signatureAlgorithms", JSONArray(d.signatureAlgorithms))
                        put("digestAlgorithms", JSONArray(d.digestAlgorithms))
                        put("sdkRange", d.sdkRange ?: JSONObject.NULL)
                        put("notes", d.notes ?: JSONObject.NULL)
                    })
                }
            })
            put("certificates", JSONArray().apply {
                r.certificates.forEach { c ->
                    put(JSONObject().apply {
                        put("index", c.index)
                        put("schemeTags", JSONArray(c.schemeTags))
                        put("knownSignerHint", c.knownSignerHint ?: JSONObject.NULL)
                        put("type", c.type)
                        put("version", c.version)
                        put("serialNumberDecimal", c.serialNumberDecimal)
                        put("serialNumberHex", c.serialNumberHex)
                        put("subject", c.subjectDn)
                        put("issuer", c.issuerDn)
                        put("isSelfSigned", c.isSelfSigned)
                        put("notBeforeMs", c.notBeforeMs)
                        put("notAfterMs", c.notAfterMs)
                        put("daysRemaining", c.daysRemaining)
                        put("validityStatus", c.validityStatus.name)
                        put("signatureAlgorithm", c.sigAlgName)
                        put("signatureAlgorithmOid", c.sigAlgOid)
                        put("hashCodeHex", c.hashCodeHex)
                        put("hashCodeInt", c.hashCodeInt)
                        put("crc32Hex", c.crc32Hex)
                        put("crc32Long", c.crc32Long)
                        put("md5", c.md5)
                        put("sha1", c.sha1)
                        put("sha1Colon", c.sha1Colon)
                        put("sha224", c.sha224)
                        put("sha256", c.sha256)
                        put("sha256Colon", c.sha256Colon)
                        put("sha384", c.sha384)
                        put("sha512", c.sha512)
                        put("certBase64", c.certBase64)
                        put("signatureBitsHex", c.signatureBitsHex)
                        put("publicKeySummary", c.publicKeySummary)
                        put("publicKeyAlgorithm", c.publicKeyAlgorithm)
                        put("publicKeySizeBits", c.publicKeySizeBits)
                        put("publicKeySpkiSha256", c.publicKeySpkiSha256)
                        put("signatureBase64", c.signatureBase64)
                        put("keyUsage", JSONArray(c.keyUsage))
                        put("extendedKeyUsage", JSONArray(c.extendedKeyUsage))
                        put("basicConstraints", c.basicConstraints ?: JSONObject.NULL)
                        put("subjectKeyIdentifier", c.subjectKeyIdentifier ?: JSONObject.NULL)
                        put("authorityKeyIdentifier", c.authorityKeyIdentifier ?: JSONObject.NULL)
                    })
                }
            })
            put("signingBlock", JSONObject().apply {
                put("present", r.signingBlockInfo.present)
                put("offset", r.signingBlockInfo.blockOffset)
                put("sizeBytes", r.signingBlockInfo.blockSizeBytes)
                put("pairs", JSONArray().apply {
                    r.signingBlockInfo.pairs.forEach { p ->
                        put(JSONObject().apply {
                            put("id", p.idHex)
                            put("name", p.name)
                            put("sizeBytes", p.sizeBytes)
                        })
                    }
                })
                put("v4IdsigFound", r.signingBlockInfo.v4IdsigFound)
                put("v4Verified", r.signingBlockInfo.v4Verified)
                put("contentDigestAlgorithms", JSONArray(r.signingBlockInfo.contentDigestAlgorithms))
            })
            put("errors", JSONArray(r.errors))
            put("warnings", JSONArray(r.warnings))
        }
    }
}
