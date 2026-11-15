package com.example.crypto

import com.example.model.ApkVerificationReport
import com.example.model.ClonedKeySpec
import com.example.model.RdnSlot
import com.example.model.SignatureSchemeType
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.TimeUnit

object KeyCloner {

    fun buildCloneSpecFromReport(
        report: ApkVerificationReport,
        defaultPassword: String = "signerlab"
    ): ClonedKeySpec {
        val certDetails = report.certificates.firstOrNull()
            ?: throw IllegalStateException("No X.509 certificate found in target APK")

        val x509 = decodeX509FromBase64(certDetails.certBase64)
        val parsedRdns = parseRfc2253Rdns(certDetails.subjectDn)

        val cn = findRdnValue(parsedRdns, "CN") ?: report.appLabel
        val ou = findRdnValue(parsedRdns, "OU") ?: ""
        val org = findRdnValue(parsedRdns, "O") ?: ""
        val locality = findRdnValue(parsedRdns, "L") ?: ""
        val state = findRdnValue(parsedRdns, "ST", "S") ?: ""
        val country = findRdnValue(parsedRdns, "C") ?: ""
        val email = findRdnValue(parsedRdns, "E", "EMAIL", "EMAILADDRESS", "1.2.840.113549.1.9.1") ?: ""

        val durationDays = TimeUnit.MILLISECONDS
            .toDays((certDetails.notAfterMs - certDetails.notBeforeMs).coerceAtLeast(0L))
            .coerceAtLeast(365L)

        val newSerial = X509DerBuilder.generateRandomPositiveSerial()
        val newSerialDec = newSerial.toString()
        val newSerialHex = "0x" + newSerial.toString(16)

        val safeAliasBase = (report.packageName ?: report.appLabel)
            .lowercase(Locale.US)
            .replace(Regex("[^a-z0-9_]+"), "_")
            .trim('_')
            .take(24)
            .ifBlank { "cloned" }

        val refreshedCn = if (cn.isNotBlank()) "$cn [Renewed]" else "SignerLAB Cloned Key"

        val bcPathLen = x509.basicConstraints
        val isCa = bcPathLen >= 0

        val detected = report.detectedSchemes
        val useV1 = detected.contains(SignatureSchemeType.V1) || detected.isEmpty()
        val useV2 = detected.contains(SignatureSchemeType.V2) || detected.isEmpty()
        val useV3 = detected.contains(SignatureSchemeType.V3)
        val useV4 = detected.contains(SignatureSchemeType.V4)

        return ClonedKeySpec(
            sourceApkPath = report.filePath,
            sourceAppLabel = report.appLabel,
            sourceReport = report,
            sourceCert = certDetails,
            keyAlgorithm = certDetails.publicKeyAlgorithm,
            keySizeBits = certDetails.publicKeySizeBits.takeIf { it > 0 } ?: 2048,
            sigAlgName = certDetails.sigAlgName,
            x509Version = certDetails.version,
            validityDays = durationDays,
            orderedRdnSlots = parsedRdns,
            keyUsageBooleans = x509.keyUsage,
            extendedKeyUsageOids = certDetails.extendedKeyUsage,
            basicConstraintsIsCa = isCa,
            basicConstraintsPathLen = if (isCa && bcPathLen != Int.MAX_VALUE) bcPathLen else null,
            includeSki = certDetails.subjectKeyIdentifier != null || certDetails.version >= 3,
            includeAki = certDetails.authorityKeyIdentifier != null,
            newAlias = "${safeAliasBase}_upd",
            newPassword = defaultPassword,
            newCommonName = refreshedCn,
            newOrgUnit = ou,
            newOrganization = org,
            newLocality = locality,
            newState = state,
            newCountry = country,
            newEmail = email,
            newSerialNumberDecimal = newSerialDec,
            newSerialNumberHex = newSerialHex,
            newValidityDays = durationDays,
            signV1 = useV1,
            signV2 = useV2,
            signV3 = useV3,
            signV4 = useV4
        )
    }

    fun generateFromCloneSpec(spec: ClonedKeySpec): Pair<PrivateKey, X509Certificate> {
        val keyPair = X509DerBuilder.generateKeyPair(spec.keyAlgorithm, spec.keySizeBits)
        val nowMs = System.currentTimeMillis()
        val afterMs = nowMs + TimeUnit.DAYS.toMillis(spec.newValidityDays.coerceAtLeast(1L))
        val serial = runCatching { BigInteger(spec.newSerialNumberDecimal.trim()) }
            .getOrElse { X509DerBuilder.generateRandomPositiveSerial() }

        // Rebuild ordered RDN list preserving the exact sequence of target attributes, substituting edited identity
        val rebuiltRdns = mutableListOf<RdnSlot>()
        val usedKeys = mutableSetOf<String>()

        fun valueForKey(rawKey: String): String? {
            val k = rawKey.trim().uppercase(Locale.US)
            return when (k) {
                "E", "EMAIL", "EMAILADDRESS", "1.2.840.113549.1.9.1" -> {
                    usedKeys += "E"
                    spec.newEmail
                }
                "CN" -> {
                    usedKeys += "CN"
                    spec.newCommonName
                }
                "OU" -> {
                    usedKeys += "OU"
                    spec.newOrgUnit
                }
                "O" -> {
                    usedKeys += "O"
                    spec.newOrganization
                }
                "L" -> {
                    usedKeys += "L"
                    spec.newLocality
                }
                "ST", "S" -> {
                    usedKeys += "ST"
                    spec.newState
                }
                "C" -> {
                    usedKeys += "C"
                    spec.newCountry
                }
                else -> null
            }
        }

        spec.orderedRdnSlots.forEach { slot ->
            val mapped = valueForKey(slot.key)
            if (mapped != null) {
                if (mapped.isNotBlank()) rebuiltRdns += RdnSlot(slot.key, mapped)
            } else if (slot.value.isNotBlank()) {
                rebuiltRdns += slot
            }
        }

        // Append any newly filled fields not originally in target DN
        if ("CN" !in usedKeys && spec.newCommonName.isNotBlank()) rebuiltRdns += RdnSlot("CN", spec.newCommonName)
        if ("OU" !in usedKeys && spec.newOrgUnit.isNotBlank()) rebuiltRdns += RdnSlot("OU", spec.newOrgUnit)
        if ("O" !in usedKeys && spec.newOrganization.isNotBlank()) rebuiltRdns += RdnSlot("O", spec.newOrganization)
        if ("L" !in usedKeys && spec.newLocality.isNotBlank()) rebuiltRdns += RdnSlot("L", spec.newLocality)
        if ("ST" !in usedKeys && spec.newState.isNotBlank()) rebuiltRdns += RdnSlot("ST", spec.newState)
        if ("C" !in usedKeys && spec.newCountry.isNotBlank()) rebuiltRdns += RdnSlot("C", spec.newCountry)
        if ("E" !in usedKeys && spec.newEmail.isNotBlank()) rebuiltRdns += RdnSlot("E", spec.newEmail)

        val certSpec = X509DerBuilder.CertificateSpec(
            serialNumber = serial,
            notBeforeMs = nowMs,
            notAfterMs = afterMs,
            orderedRdns = rebuiltRdns,
            sigAlgName = spec.sigAlgName,
            keyUsageBits = spec.keyUsageBooleans,
            extendedKeyUsageOids = spec.extendedKeyUsageOids,
            basicConstraintsIsCa = spec.basicConstraintsIsCa,
            basicConstraintsPathLen = spec.basicConstraintsPathLen,
            includeBasicConstraints = spec.sourceCert.basicConstraints != null,
            includeSki = spec.includeSki,
            includeAki = spec.includeAki
        )

        val cert = X509DerBuilder.buildSelfSignedCertificate(keyPair, certSpec)
        return keyPair.private to cert
    }

    private fun decodeX509FromBase64(b64: String): X509Certificate {
        val raw = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(raw)) as X509Certificate
    }

    internal fun parseRfc2253Rdns(dn: String): List<RdnSlot> {
        val parts = mutableListOf<String>()
        val cur = StringBuilder()
        var escaped = false
        var quoted = false
        for (ch in dn) {
            when {
                escaped -> {
                    cur.append(ch)
                    escaped = false
                }
                ch == '\\' -> {
                    cur.append(ch)
                    escaped = true
                }
                ch == '"' -> {
                    quoted = !quoted
                    cur.append(ch)
                }
                ch == ',' && !quoted -> {
                    parts += cur.toString().trim()
                    cur.clear()
                }
                else -> cur.append(ch)
            }
        }
        if (cur.isNotBlank()) parts += cur.toString().trim()

        return parts.mapNotNull { token ->
            val eqIdx = token.indexOf('=')
            if (eqIdx <= 0) return@mapNotNull null
            val rawKey = token.substring(0, eqIdx).trim()
            val rawVal = token.substring(eqIdx + 1).trim()
            val decodedVal = decodeRfc2253Value(rawVal)
            val normalizedKey = if (rawKey == "1.2.840.113549.1.9.1") "E" else rawKey
            RdnSlot(normalizedKey, decodedVal)
        }
    }

    private fun decodeRfc2253Value(raw: String): String {
        if (raw.startsWith("#") && raw.length >= 6 && raw.length % 2 == 1) {
            return try {
                val hex = raw.substring(1)
                val bytes = ByteArray(hex.length / 2) { idx ->
                    hex.substring(idx * 2, idx * 2 + 2).toInt(16).toByte()
                }
                // Simple ASN.1 TLV strip (tag + 1-byte length or multi-byte length)
                if (bytes.size >= 2) {
                    val lenByte = bytes[1].toInt() and 0xFF
                    val offset = if (lenByte < 0x80) 2 else 2 + (lenByte and 0x7F)
                    if (offset <= bytes.size) {
                        return String(bytes, offset, bytes.size - offset, Charsets.UTF_8)
                    }
                }
                raw
            } catch (_: Exception) {
                raw
            }
        }
        return raw.replace("\\,", ",").replace("\\+", "+").trim('"')
    }

    private fun findRdnValue(rdns: List<RdnSlot>, vararg keys: String): String? {
        val targetSet = keys.map { it.uppercase(Locale.US) }.toSet()
        return rdns.firstOrNull { it.key.uppercase(Locale.US) in targetSet }?.value
    }
}
