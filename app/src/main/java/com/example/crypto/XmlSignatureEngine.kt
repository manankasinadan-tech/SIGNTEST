package com.example.crypto

import com.example.model.CertificateDetails
import com.example.model.XmlSignatureDocument
import com.example.model.XmlSignatureFormat
import com.example.model.XmlSignatureReference
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.ByteArrayInputStream
import java.io.StringReader
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

object XmlSignatureEngine {

    private data class CertDigestBundle(
        val sha256: String,
        val sha1: String,
        val sha512: String
    )

    private data class ActiveContext(
        val tagName: String,
        val packages: MutableList<String> = mutableListOf(),
        val seinfoList: MutableList<String> = mutableListOf(),
        val refIds: MutableList<Int> = mutableListOf()
    )

    private val SIGNATURE_CONTEXT_KEYWORDS = listOf(
        "sig", "cert", "digest", "hash", "sha256", "sha1", "sha512",
        "thumb", "finger", "pin", "signer", "key", "mac"
    )

    private val DER_HEX_REGEX = Regex("\\b[0-9a-fA-F]{128,}\\b")
    private val BASE64_CERT_REGEX = Regex("MII[A-Za-z0-9+/=\\r\\n]{80,}")
    private val SHA512_COLON_REGEX = Regex("\\b(?:[0-9a-fA-F]{2}:){63}[0-9a-fA-F]{2}\\b")
    private val SHA256_COLON_REGEX = Regex("\\b(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}\\b")
    private val SHA1_COLON_REGEX = Regex("\\b(?:[0-9a-fA-F]{2}:){19}[0-9a-fA-F]{2}\\b")
    private val SHA512_PLAIN_REGEX = Regex("\\b[0-9a-fA-F]{128}\\b")
    private val SHA256_PLAIN_REGEX = Regex("\\b[0-9a-fA-F]{64}\\b")
    private val SHA1_PLAIN_REGEX = Regex("\\b[0-9a-fA-F]{40}\\b")

    fun isBinaryXml(bytes: ByteArray): Boolean {
        if (bytes.size < 4) return false
        // Android compiled binary XML header: 0x00080003 little-endian -> 03 00 08 00
        if (bytes[0] == 0x03.toByte() && bytes[1] == 0x00.toByte() &&
            bytes[2] == 0x08.toByte() && bytes[3] == 0x00.toByte()
        ) {
            return true
        }
        val sampleLen = minOf(bytes.size, 512)
        var nonPrintable = 0
        for (i in 0 until sampleLen) {
            val b = bytes[i].toInt() and 0xFF
            if (b == 0) return true
            if (b < 0x09 || (b in 0x0E..0x1F)) nonPrintable++
        }
        return nonPrintable > sampleLen / 8
    }

    fun inferXmlKind(relativePath: String, rootTag: String?): String {
        val lowerPath = relativePath.lowercase(Locale.US)
        val lowerTag = rootTag?.lowercase(Locale.US) ?: ""
        return when {
            lowerPath.contains("mac_permissions") || lowerTag == "policy" -> "SELinux MAC Permissions"
            lowerPath.contains("privapp-permissions") || lowerTag == "permissions" -> "Priv-App / Platform Permissions"
            lowerPath.endsWith("packages.xml") || lowerTag == "packages" -> "PackageManager Registry"
            lowerPath.contains("known-signer") || lowerTag.contains("known-signer") -> "Known Signer Policy"
            lowerPath.contains("default-permissions") -> "Default Permissions"
            lowerPath.contains("sysconfig") || lowerTag == "config" -> "SysConfig"
            else -> "XML Permission / Config"
        }
    }

    fun parseXmlDocument(
        path: String,
        relativePath: String,
        rawText: String,
        viaRoot: Boolean,
        knownSha256: Set<String> = emptySet(),
        knownSha1: Set<String> = emptySet(),
        knownSha512: Set<String> = emptySet()
    ): XmlSignatureDocument? {
        val trimmed = rawText.trim()
        if (trimmed.isEmpty() || !trimmed.startsWith("<")) return null

        val extractedRefs = mutableListOf<XmlSignatureReference>()
        var rootTag: String? = null
        val contextStack = ArrayDeque<ActiveContext>()

        try {
            val factory = XmlPullParserFactory.newInstance()
            factory.isNamespaceAware = false
            val parser = factory.newPullParser()
            parser.setInput(StringReader(rawText))

            var eventType = parser.eventType
            while (eventType != XmlPullParser.END_DOCUMENT) {
                when (eventType) {
                    XmlPullParser.START_TAG -> {
                        val tag = parser.name ?: ""
                        if (rootTag == null) rootTag = tag
                        val lowerTag = tag.lowercase(Locale.US)

                        if (lowerTag in setOf("signer", "package", "sigs", "cert", "pastSigs".lowercase(Locale.US), "known-signer")) {
                            contextStack.addLast(ActiveContext(tag))
                        }

                        var seinfoInTag: String? = null
                        var packageInTag: String? = null
                        for (i in 0 until parser.attributeCount) {
                            val attrName = parser.getAttributeName(i) ?: continue
                            val attrVal = parser.getAttributeValue(i) ?: continue
                            val lowerAttr = attrName.lowercase(Locale.US)
                            if (lowerTag == "seinfo" && lowerAttr == "value") {
                                seinfoInTag = attrVal.trim()
                            } else if ((lowerTag == "package" || lowerTag == "privapp-permissions" || lowerTag == "known-signer") &&
                                (lowerAttr == "name" || lowerAttr == "package")
                            ) {
                                packageInTag = attrVal.trim()
                            }
                        }

                        seinfoInTag?.let { s ->
                            contextStack.lastOrNull()?.seinfoList?.add(s)
                        }
                        packageInTag?.let { pkg ->
                            contextStack.lastOrNull()?.packages?.add(pkg)
                        }

                        val activePackage = packageInTag ?: contextStack.lastOrNull { it.packages.isNotEmpty() }?.packages?.lastOrNull()
                        val activeSeinfo = seinfoInTag ?: contextStack.lastOrNull { it.seinfoList.isNotEmpty() }?.seinfoList?.lastOrNull()

                        for (i in 0 until parser.attributeCount) {
                            val attrName = parser.getAttributeName(i) ?: continue
                            val attrVal = parser.getAttributeValue(i) ?: continue
                            val hasSigContext = isSignatureContext(tag, attrName)
                            val found = extractTokensFromString(
                                input = attrVal,
                                tagName = tag,
                                attributeName = attrName,
                                hasSigContext = hasSigContext,
                                knownSha256 = knownSha256,
                                knownSha1 = knownSha1,
                                knownSha512 = knownSha512,
                                baseIndex = extractedRefs.size,
                                seinfo = activeSeinfo,
                                initialPackages = listOfNotNull(activePackage)
                            )
                            found.forEach { ref ->
                                val idx = extractedRefs.size
                                extractedRefs += ref
                                contextStack.lastOrNull()?.refIds?.add(idx)
                            }
                        }
                    }

                    XmlPullParser.TEXT -> {
                        val txt = parser.text
                        if (!txt.isNullOrBlank()) {
                            val currentTag = parser.name ?: contextStack.lastOrNull()?.tagName ?: "text"
                            val hasSigContext = isSignatureContext(currentTag, null)
                            val activePackage = contextStack.lastOrNull { it.packages.isNotEmpty() }?.packages?.lastOrNull()
                            val activeSeinfo = contextStack.lastOrNull { it.seinfoList.isNotEmpty() }?.seinfoList?.lastOrNull()
                            val found = extractTokensFromString(
                                input = txt,
                                tagName = currentTag,
                                attributeName = null,
                                hasSigContext = hasSigContext,
                                knownSha256 = knownSha256,
                                knownSha1 = knownSha1,
                                knownSha512 = knownSha512,
                                baseIndex = extractedRefs.size,
                                seinfo = activeSeinfo,
                                initialPackages = listOfNotNull(activePackage)
                            )
                            found.forEach { ref ->
                                val idx = extractedRefs.size
                                extractedRefs += ref
                                contextStack.lastOrNull()?.refIds?.add(idx)
                            }
                        }
                    }

                    XmlPullParser.END_TAG -> {
                        val tag = parser.name ?: ""
                        if (contextStack.isNotEmpty() && contextStack.last().tagName == tag) {
                            val popped = contextStack.removeLast()
                            // Backfill seinfo and associatedPackages onto references collected inside this block
                            if (popped.refIds.isNotEmpty()) {
                                val seinfo = popped.seinfoList.firstOrNull()
                                val pkgs = popped.packages.distinct()
                                popped.refIds.forEach { idx ->
                                    if (idx in extractedRefs.indices) {
                                        val cur = extractedRefs[idx]
                                        extractedRefs[idx] = cur.copy(
                                            seinfo = cur.seinfo ?: seinfo,
                                            associatedPackages = (cur.associatedPackages + pkgs).distinct()
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
                eventType = parser.next()
            }
        } catch (_: Exception) {
            // Fall through to raw scan fallback if XML is malformed/truncated
        }

        // Raw fallback pass to catch any tokens missed due to malformed XML or comments/CDATA
        val seenRaw = extractedRefs.map { it.rawValue }.toMutableSet()
        val fallbackTokens = extractTokensFromString(
            input = rawText,
            tagName = "raw",
            attributeName = null,
            hasSigContext = true,
            knownSha256 = knownSha256,
            knownSha1 = knownSha1,
            knownSha512 = knownSha512,
            baseIndex = extractedRefs.size,
            seinfo = null,
            initialPackages = emptyList()
        ).filter { ref ->
            // Only keep fallback tokens if either X.509 cert decoded OR matching a known APK digest OR colon-formatted
            val matchesKnown = (ref.normalizedSha256 != null && ref.normalizedSha256 in knownSha256) ||
                (ref.normalizedSha1 != null && ref.normalizedSha1 in knownSha1) ||
                (ref.normalizedSha512 != null && ref.normalizedSha512 in knownSha512)
            val isCert = ref.format in setOf(
                XmlSignatureFormat.DER_HEX_LOWER,
                XmlSignatureFormat.DER_HEX_UPPER,
                XmlSignatureFormat.DER_BASE64
            )
            val isColon = ref.format.name.contains("COLON")
            (isCert || matchesKnown || isColon) && seenRaw.add(ref.rawValue)
        }
        extractedRefs += fallbackTokens

        if (extractedRefs.isEmpty()) return null

        val kind = inferXmlKind(relativePath, rootTag)
        val snippet = rawText.lineSequence().take(10).joinToString("\n").take(600)
        return XmlSignatureDocument(
            path = path,
            relativePath = relativePath,
            xmlKind = kind,
            viaRoot = viaRoot,
            references = extractedRefs,
            snippet = snippet
        )
    }

    fun updateXmlContent(
        rawXml: String,
        references: List<XmlSignatureReference>,
        oldSha256ToNewCert: Map<String, CertificateDetails>,
        oldSha1ToNewCert: Map<String, CertificateDetails> = emptyMap(),
        oldSha512ToNewCert: Map<String, CertificateDetails> = emptyMap()
    ): Pair<String, Int> {
        if (references.isEmpty()) return rawXml to 0
        var updated = rawXml
        var replacedRefs = 0

        // Process longer tokens first (DER -> SHA512 -> SHA256 -> SHA1) to eliminate substring overlap
        val orderedRefs = references.distinctBy { it.rawValue }
            .sortedByDescending { it.rawValue.length }

        for (ref in orderedRefs) {
            val targetCert = ref.normalizedSha256?.let { oldSha256ToNewCert[it] }
                ?: ref.normalizedSha1?.let { oldSha1ToNewCert[it] }
                ?: ref.normalizedSha512?.let { oldSha512ToNewCert[it] }
                ?: continue

            val formattedReplacement = formatCertificateForReference(targetCert, ref.format)
            if (formattedReplacement != ref.rawValue && updated.contains(ref.rawValue)) {
                val occurrences = countOccurrences(updated, ref.rawValue)
                updated = updated.replace(ref.rawValue, formattedReplacement)
                replacedRefs += occurrences
            }
        }
        return updated to replacedRefs
    }

    fun formatCertificateForReference(cert: CertificateDetails, format: XmlSignatureFormat): String {
        return when (format) {
            XmlSignatureFormat.DER_HEX_LOWER -> cert.signatureBitsHex.lowercase(Locale.US)
            XmlSignatureFormat.DER_HEX_UPPER -> cert.signatureBitsHex.uppercase(Locale.US)
            XmlSignatureFormat.DER_BASE64 -> cert.certBase64
            XmlSignatureFormat.SHA256_PLAIN_LOWER -> cert.sha256.lowercase(Locale.US)
            XmlSignatureFormat.SHA256_PLAIN_UPPER -> cert.sha256.uppercase(Locale.US)
            XmlSignatureFormat.SHA256_COLON_LOWER -> cert.sha256Colon.lowercase(Locale.US)
            XmlSignatureFormat.SHA256_COLON_UPPER -> cert.sha256Colon.uppercase(Locale.US)
            XmlSignatureFormat.SHA1_PLAIN_LOWER -> cert.sha1.lowercase(Locale.US)
            XmlSignatureFormat.SHA1_PLAIN_UPPER -> cert.sha1.uppercase(Locale.US)
            XmlSignatureFormat.SHA1_COLON_LOWER -> cert.sha1Colon.lowercase(Locale.US)
            XmlSignatureFormat.SHA1_COLON_UPPER -> cert.sha1Colon.uppercase(Locale.US)
            XmlSignatureFormat.SHA512_PLAIN_LOWER -> cert.sha512.lowercase(Locale.US)
            XmlSignatureFormat.SHA512_PLAIN_UPPER -> cert.sha512.uppercase(Locale.US)
            XmlSignatureFormat.SHA512_COLON_LOWER -> CryptoUtils.toColonUpperHex(cert.sha512).lowercase(Locale.US)
            XmlSignatureFormat.SHA512_COLON_UPPER -> CryptoUtils.toColonUpperHex(cert.sha512).uppercase(Locale.US)
        }
    }

    private fun extractTokensFromString(
        input: String,
        tagName: String,
        attributeName: String?,
        hasSigContext: Boolean,
        knownSha256: Set<String>,
        knownSha1: Set<String>,
        knownSha512: Set<String>,
        baseIndex: Int,
        seinfo: String?,
        initialPackages: List<String>
    ): List<XmlSignatureReference> {
        val results = mutableListOf<XmlSignatureReference>()
        val consumedRanges = mutableListOf<IntRange>()

        fun overlapsConsumed(range: IntRange): Boolean {
            return consumedRanges.any { it.first <= range.last && range.first <= it.last }
        }

        // 1. DER Hex (X.509 certificate encoded as hex)
        DER_HEX_REGEX.findAll(input).forEach { m ->
            val token = m.value
            if (token.length % 2 != 0) return@forEach
            val bundle = tryDecodeX509Hex(token) ?: return@forEach
            val isUpper = token.any { it in 'A'..'F' }
            consumedRanges += m.range
            results += XmlSignatureReference(
                id = "ref_${baseIndex + results.size}",
                rawValue = token,
                normalizedSha256 = bundle.sha256,
                normalizedSha1 = bundle.sha1,
                normalizedSha512 = bundle.sha512,
                format = if (isUpper) XmlSignatureFormat.DER_HEX_UPPER else XmlSignatureFormat.DER_HEX_LOWER,
                tagName = tagName,
                attributeName = attributeName,
                seinfo = seinfo,
                associatedPackages = initialPackages
            )
        }

        // 2. Base64 DER X.509
        BASE64_CERT_REGEX.findAll(input).forEach { m ->
            if (overlapsConsumed(m.range)) return@forEach
            val token = m.value.trim()
            val bundle = tryDecodeX509Base64(token) ?: return@forEach
            consumedRanges += m.range
            results += XmlSignatureReference(
                id = "ref_${baseIndex + results.size}",
                rawValue = token,
                normalizedSha256 = bundle.sha256,
                normalizedSha1 = bundle.sha1,
                normalizedSha512 = bundle.sha512,
                format = XmlSignatureFormat.DER_BASE64,
                tagName = tagName,
                attributeName = attributeName,
                seinfo = seinfo,
                associatedPackages = initialPackages
            )
        }

        // 3. Colon-separated SHA-512
        SHA512_COLON_REGEX.findAll(input).forEach { m ->
            if (overlapsConsumed(m.range)) return@forEach
            val token = m.value
            val norm = token.replace(":", "").lowercase(Locale.US)
            if (hasSigContext || norm in knownSha512) {
                val isUpper = token.any { it in 'A'..'F' }
                consumedRanges += m.range
                results += XmlSignatureReference(
                    id = "ref_${baseIndex + results.size}",
                    rawValue = token,
                    normalizedSha256 = null,
                    normalizedSha1 = null,
                    normalizedSha512 = norm,
                    format = if (isUpper) XmlSignatureFormat.SHA512_COLON_UPPER else XmlSignatureFormat.SHA512_COLON_LOWER,
                    tagName = tagName,
                    attributeName = attributeName,
                    seinfo = seinfo,
                    associatedPackages = initialPackages
                )
            }
        }

        // 4. Plain SHA-512 (128 hex chars)
        SHA512_PLAIN_REGEX.findAll(input).forEach { m ->
            if (overlapsConsumed(m.range)) return@forEach
            val token = m.value
            val norm = token.lowercase(Locale.US)
            if (hasSigContext || norm in knownSha512) {
                val isUpper = token.any { it in 'A'..'F' }
                consumedRanges += m.range
                results += XmlSignatureReference(
                    id = "ref_${baseIndex + results.size}",
                    rawValue = token,
                    normalizedSha256 = null,
                    normalizedSha1 = null,
                    normalizedSha512 = norm,
                    format = if (isUpper) XmlSignatureFormat.SHA512_PLAIN_UPPER else XmlSignatureFormat.SHA512_PLAIN_LOWER,
                    tagName = tagName,
                    attributeName = attributeName,
                    seinfo = seinfo,
                    associatedPackages = initialPackages
                )
            }
        }

        // 5. Colon-separated SHA-256
        SHA256_COLON_REGEX.findAll(input).forEach { m ->
            if (overlapsConsumed(m.range)) return@forEach
            val token = m.value
            val norm = token.replace(":", "").lowercase(Locale.US)
            if (hasSigContext || norm in knownSha256) {
                val isUpper = token.any { it in 'A'..'F' }
                consumedRanges += m.range
                results += XmlSignatureReference(
                    id = "ref_${baseIndex + results.size}",
                    rawValue = token,
                    normalizedSha256 = norm,
                    normalizedSha1 = null,
                    normalizedSha512 = null,
                    format = if (isUpper) XmlSignatureFormat.SHA256_COLON_UPPER else XmlSignatureFormat.SHA256_COLON_LOWER,
                    tagName = tagName,
                    attributeName = attributeName,
                    seinfo = seinfo,
                    associatedPackages = initialPackages
                )
            }
        }

        // 6. Plain SHA-256 (64 hex chars)
        SHA256_PLAIN_REGEX.findAll(input).forEach { m ->
            if (overlapsConsumed(m.range)) return@forEach
            val token = m.value
            val norm = token.lowercase(Locale.US)
            if (hasSigContext || norm in knownSha256) {
                val isUpper = token.any { it in 'A'..'F' }
                consumedRanges += m.range
                results += XmlSignatureReference(
                    id = "ref_${baseIndex + results.size}",
                    rawValue = token,
                    normalizedSha256 = norm,
                    normalizedSha1 = null,
                    normalizedSha512 = null,
                    format = if (isUpper) XmlSignatureFormat.SHA256_PLAIN_UPPER else XmlSignatureFormat.SHA256_PLAIN_LOWER,
                    tagName = tagName,
                    attributeName = attributeName,
                    seinfo = seinfo,
                    associatedPackages = initialPackages
                )
            }
        }

        // 7. Colon-separated SHA-1
        SHA1_COLON_REGEX.findAll(input).forEach { m ->
            if (overlapsConsumed(m.range)) return@forEach
            val token = m.value
            val norm = token.replace(":", "").lowercase(Locale.US)
            if (hasSigContext || norm in knownSha1) {
                val isUpper = token.any { it in 'A'..'F' }
                consumedRanges += m.range
                results += XmlSignatureReference(
                    id = "ref_${baseIndex + results.size}",
                    rawValue = token,
                    normalizedSha256 = null,
                    normalizedSha1 = norm,
                    normalizedSha512 = null,
                    format = if (isUpper) XmlSignatureFormat.SHA1_COLON_UPPER else XmlSignatureFormat.SHA1_COLON_LOWER,
                    tagName = tagName,
                    attributeName = attributeName,
                    seinfo = seinfo,
                    associatedPackages = initialPackages
                )
            }
        }

        // 8. Plain SHA-1 (40 hex chars)
        SHA1_PLAIN_REGEX.findAll(input).forEach { m ->
            if (overlapsConsumed(m.range)) return@forEach
            val token = m.value
            val norm = token.lowercase(Locale.US)
            if (hasSigContext || norm in knownSha1) {
                val isUpper = token.any { it in 'A'..'F' }
                consumedRanges += m.range
                results += XmlSignatureReference(
                    id = "ref_${baseIndex + results.size}",
                    rawValue = token,
                    normalizedSha256 = null,
                    normalizedSha1 = norm,
                    normalizedSha512 = null,
                    format = if (isUpper) XmlSignatureFormat.SHA1_PLAIN_UPPER else XmlSignatureFormat.SHA1_PLAIN_LOWER,
                    tagName = tagName,
                    attributeName = attributeName,
                    seinfo = seinfo,
                    associatedPackages = initialPackages
                )
            }
        }

        return results
    }

    private fun isSignatureContext(tagName: String, attrName: String?): Boolean {
        val combined = "$tagName ${attrName ?: ""}".lowercase(Locale.US)
        return SIGNATURE_CONTEXT_KEYWORDS.any { combined.contains(it) }
    }

    private fun tryDecodeX509Hex(hex: String): CertDigestBundle? {
        return try {
            val bytes = ByteArray(hex.length / 2) { idx ->
                hex.substring(idx * 2, idx * 2 + 2).toInt(16).toByte()
            }
            if (bytes.size < 64 || bytes[0] != 0x30.toByte()) return null
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate ?: return null
            val der = cert.encoded
            CertDigestBundle(
                sha256 = CryptoUtils.digestHex(der, "SHA-256"),
                sha1 = CryptoUtils.digestHex(der, "SHA-1"),
                sha512 = CryptoUtils.digestHex(der, "SHA-512")
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun tryDecodeX509Base64(b64: String): CertDigestBundle? {
        return try {
            val cleaned = b64.replace(Regex("\\s+"), "")
            val bytes = java.util.Base64.getDecoder().decode(cleaned)
            if (bytes.size < 64 || bytes[0] != 0x30.toByte()) return null
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate ?: return null
            val der = cert.encoded
            CertDigestBundle(
                sha256 = CryptoUtils.digestHex(der, "SHA-256"),
                sha1 = CryptoUtils.digestHex(der, "SHA-1"),
                sha512 = CryptoUtils.digestHex(der, "SHA-512")
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun countOccurrences(haystack: String, needle: String): Int {
        if (needle.isEmpty()) return 0
        var count = 0
        var idx = 0
        while (true) {
            val found = haystack.indexOf(needle, idx)
            if (found < 0) break
            count++
            idx = found + needle.length
        }
        return count
    }
}
