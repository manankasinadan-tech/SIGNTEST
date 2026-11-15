package com.example.crypto

import com.example.model.RdnSlot
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Pure-Kotlin ASN.1 DER X.509 v3 Certificate Builder.
 * Avoids private `sun.security.*` APIs (unavailable on Android ART) and heavy BouncyCastle dependencies.
 */
object X509DerBuilder {

    data class CertificateSpec(
        val serialNumber: BigInteger,
        val notBeforeMs: Long,
        val notAfterMs: Long,
        val orderedRdns: List<RdnSlot>,
        val sigAlgName: String,
        val keyUsageBits: BooleanArray? = booleanArrayOf(true, false, false, false, false, false, false, false, false),
        val extendedKeyUsageOids: List<String> = emptyList(),
        val basicConstraintsIsCa: Boolean = false,
        val basicConstraintsPathLen: Int? = null,
        val includeBasicConstraints: Boolean = true,
        val includeSki: Boolean = true,
        val includeAki: Boolean = true
    )

    private val ATTRIBUTE_OIDS = mapOf(
        "C" to "2.5.4.6",
        "ST" to "2.5.4.8",
        "S" to "2.5.4.8",
        "L" to "2.5.4.7",
        "O" to "2.5.4.10",
        "OU" to "2.5.4.11",
        "CN" to "2.5.4.3",
        "E" to "1.2.840.113549.1.9.1",
        "EMAIL" to "1.2.840.113549.1.9.1",
        "EMAILADDRESS" to "1.2.840.113549.1.9.1",
        "1.2.840.113549.1.9.1" to "1.2.840.113549.1.9.1"
    )

    private val SIG_ALG_OIDS = mapOf(
        "SHA1WITHRSA" to "1.2.840.113549.1.1.5",
        "SHA224WITHRSA" to "1.2.840.113549.1.1.14",
        "SHA256WITHRSA" to "1.2.840.113549.1.1.11",
        "SHA384WITHRSA" to "1.2.840.113549.1.1.12",
        "SHA512WITHRSA" to "1.2.840.113549.1.1.13",
        "SHA1WITHECDSA" to "1.2.840.10045.4.1",
        "SHA256WITHECDSA" to "1.2.840.10045.4.3.2",
        "SHA384WITHECDSA" to "1.2.840.10045.4.3.3",
        "SHA512WITHECDSA" to "1.2.840.10045.4.3.4",
        "SHA1WITHDSA" to "1.2.840.10040.4.3",
        "SHA256WITHDSA" to "2.16.840.1.101.3.4.3.2"
    )

    fun generateKeyPair(algorithm: String, keySizeBits: Int): KeyPair {
        val normAlg = algorithm.uppercase(Locale.US)
        val rng = SecureRandom()
        return when {
            normAlg.contains("EC") -> {
                val kpg = KeyPairGenerator.getInstance("EC")
                val curveName = when {
                    keySizeBits >= 512 -> "secp521r1"
                    keySizeBits >= 384 -> "secp384r1"
                    else -> "secp256r1"
                }
                kpg.initialize(ECGenParameterSpec(curveName), rng)
                kpg.generateKeyPair()
            }
            normAlg.contains("DSA") -> {
                val safeBits = if (keySizeBits in 1024..2048) keySizeBits else 2048
                val kpg = KeyPairGenerator.getInstance("DSA")
                kpg.initialize(safeBits, rng)
                kpg.generateKeyPair()
            }
            else -> {
                val safeBits = when {
                    keySizeBits >= 4096 -> 4096
                    keySizeBits >= 3072 -> 3072
                    keySizeBits >= 2048 -> 2048
                    keySizeBits >= 1024 -> 1024
                    else -> 2048
                }
                val kpg = KeyPairGenerator.getInstance("RSA")
                kpg.initialize(safeBits, rng)
                kpg.generateKeyPair()
            }
        }
    }

    fun generateRandomPositiveSerial(): BigInteger {
        val bytes = ByteArray(8)
        SecureRandom().nextBytes(bytes)
        bytes[0] = (bytes[0].toInt() and 0x7F).toByte()
        if (bytes[0].toInt() == 0) bytes[0] = 0x42
        return BigInteger(1, bytes)
    }

    fun buildSelfSignedCertificate(keyPair: KeyPair, spec: CertificateSpec): X509Certificate {
        val sigAlgNormalized = normalizeSigAlg(spec.sigAlgName, keyPair.public.algorithm)
        val sigAlgIdDer = encodeSignatureAlgorithmIdentifier(sigAlgNormalized)

        val versionExplicit0 = derExplicitTag(0, derInteger(BigInteger.valueOf(2))) // v3 = 2
        val serialDer = derInteger(spec.serialNumber.abs().let { if (it == BigInteger.ZERO) BigInteger.ONE else it })
        val nameDer = encodeName(spec.orderedRdns)
        val validityDer = derSequence(
            encodeTime(spec.notBeforeMs),
            encodeTime(spec.notAfterMs)
        )
        val spkiDer = keyPair.public.encoded
            ?: throw IllegalStateException("Public key does not support X.509 encoding")

        val extensionsDer = buildExtensions(keyPair.public, spec)

        val tbsParts = mutableListOf(
            versionExplicit0,
            serialDer,
            sigAlgIdDer,
            nameDer,
            validityDer,
            nameDer, // Self-signed: Issuer == Subject
            spkiDer
        )
        if (extensionsDer != null) {
            tbsParts += derExplicitTag(3, extensionsDer)
        }
        val tbsCertificate = derSequence(*tbsParts.toTypedArray())

        val signer = Signature.getInstance(sigAlgNormalized)
        signer.initSign(keyPair.private, SecureRandom())
        signer.update(tbsCertificate)
        val signatureBytes = signer.sign()

        val fullCertDer = derSequence(
            tbsCertificate,
            sigAlgIdDer,
            derBitString(signatureBytes, unusedBits = 0)
        )

        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(fullCertDer)) as X509Certificate
        cert.verify(keyPair.public)
        return cert
    }

    fun normalizeSigAlg(requested: String, publicKeyAlg: String): String {
        val upper = requested.uppercase(Locale.US).replace("-", "")
        val keyAlg = publicKeyAlg.uppercase(Locale.US)
        return when {
            keyAlg.contains("EC") -> when {
                upper.contains("512") -> "SHA512withECDSA"
                upper.contains("384") -> "SHA384withECDSA"
                else -> "SHA256withECDSA"
            }
            keyAlg.contains("DSA") -> when {
                upper.contains("SHA1") -> "SHA1withDSA"
                else -> "SHA256withDSA"
            }
            else -> when {
                upper.contains("SHA512") -> "SHA512withRSA"
                upper.contains("SHA384") -> "SHA384withRSA"
                upper.contains("SHA224") -> "SHA224withRSA"
                upper.contains("SHA1") -> "SHA1withRSA"
                else -> "SHA256withRSA"
            }
        }
    }

    private fun encodeSignatureAlgorithmIdentifier(sigAlgName: String): ByteArray {
        val key = sigAlgName.uppercase(Locale.US)
        val oid = SIG_ALG_OIDS[key] ?: "1.2.840.113549.1.1.11"
        val oidBytes = derOid(oid)
        // RFC 3279 / 4055: RSA algorithms include NULL parameters; ECDSA/DSA omit NULL parameters
        return if (key.endsWith("RSA")) {
            derSequence(oidBytes, derNull())
        } else {
            derSequence(oidBytes)
        }
    }

    private fun encodeName(rdns: List<RdnSlot>): ByteArray {
        val filtered = rdns.filter { it.value.isNotBlank() }
        val effective = if (filtered.isEmpty()) listOf(RdnSlot("CN", "SignerLAB")) else filtered
        val sets = effective.map { slot ->
            val keyUpper = slot.key.trim().uppercase(Locale.US)
            val oid = ATTRIBUTE_OIDS[keyUpper]
                ?: if (slot.key.matches(Regex("""\d+(\.\d+)+"""))) slot.key else "2.5.4.3"
            val valueDer = when {
                oid == "1.2.840.113549.1.9.1" -> derIa5String(slot.value.trim())
                oid == "2.5.4.6" -> derPrintableString(slot.value.trim().take(2).uppercase(Locale.US))
                isPrintableAscii(slot.value) -> derPrintableString(slot.value.trim())
                else -> derUtf8String(slot.value.trim())
            }
            val atv = derSequence(derOid(oid), valueDer)
            derSet(atv)
        }
        return derSequence(*sets.toTypedArray())
    }

    private fun buildExtensions(publicKey: PublicKey, spec: CertificateSpec): ByteArray? {
        val extList = mutableListOf<ByteArray>()

        // 1. SubjectKeyIdentifier (2.5.29.14)
        val skiBytes = computeKeyIdentifierSha1(publicKey)
        if (spec.includeSki && skiBytes != null) {
            extList += derExtension(
                oid = "2.5.29.14",
                critical = false,
                valueDer = derOctetString(skiBytes)
            )
        }

        // 2. AuthorityKeyIdentifier (2.5.29.35)
        if (spec.includeAki && skiBytes != null) {
            val akiSeq = derSequence(derPrimitiveTag(0x80, skiBytes))
            extList += derExtension(
                oid = "2.5.29.35",
                critical = false,
                valueDer = akiSeq
            )
        }

        // 3. BasicConstraints (2.5.29.19)
        if (spec.includeBasicConstraints) {
            val bcInner = mutableListOf<ByteArray>()
            if (spec.basicConstraintsIsCa) {
                bcInner += derBoolean(true)
                spec.basicConstraintsPathLen?.let { pathLen ->
                    if (pathLen >= 0) bcInner += derInteger(BigInteger.valueOf(pathLen.toLong()))
                }
            }
            extList += derExtension(
                oid = "2.5.29.19",
                critical = spec.basicConstraintsIsCa,
                valueDer = derSequence(*bcInner.toTypedArray())
            )
        }

        // 4. KeyUsage (2.5.29.15)
        spec.keyUsageBits?.let { bits ->
            if (bits.any { it }) {
                val (bitBytes, unusedBits) = encodeBitFlags(bits)
                extList += derExtension(
                    oid = "2.5.29.15",
                    critical = true,
                    valueDer = derBitString(bitBytes, unusedBits)
                )
            }
        }

        // 5. ExtendedKeyUsage (2.5.29.37)
        if (spec.extendedKeyUsageOids.isNotEmpty()) {
            val oidParts = spec.extendedKeyUsageOids.map { derOid(it) }
            extList += derExtension(
                oid = "2.5.29.37",
                critical = false,
                valueDer = derSequence(*oidParts.toTypedArray())
            )
        }

        if (extList.isEmpty()) return null
        return derSequence(*extList.toTypedArray())
    }

    private fun computeKeyIdentifierSha1(publicKey: PublicKey): ByteArray? {
        val spki = publicKey.encoded ?: return null
        // Extract BIT STRING payload from SubjectPublicKeyInfo: SEQUENCE { algId, BIT STRING }
        return try {
            var pos = 0
            if (spki[pos++].toInt() != 0x30) return null
            pos += readLengthSize(spki, pos)
            if (spki[pos++].toInt() != 0x30) return null
            val algLenBytes = readLengthSize(spki, pos)
            val algLen = readLengthValue(spki, pos)
            pos += algLenBytes + algLen
            if (spki[pos++].toInt() != 0x03) return null
            val bitLenBytes = readLengthSize(spki, pos)
            val bitLen = readLengthValue(spki, pos)
            pos += bitLenBytes
            // skip 1 byte for unused-bits indicator
            val keyPayload = spki.copyOfRange(pos + 1, pos + bitLen)
            MessageDigest.getInstance("SHA-1").digest(keyPayload)
        } catch (_: Exception) {
            MessageDigest.getInstance("SHA-1").digest(spki)
        }
    }

    private fun readLengthSize(data: ByteArray, offset: Int): Int {
        val first = data[offset].toInt() and 0xFF
        return if (first < 0x80) 1 else 1 + (first and 0x7F)
    }

    private fun readLengthValue(data: ByteArray, offset: Int): Int {
        val first = data[offset].toInt() and 0xFF
        if (first < 0x80) return first
        val count = first and 0x7F
        var len = 0
        for (i in 1..count) {
            len = (len shl 8) or (data[offset + i].toInt() and 0xFF)
        }
        return len
    }

    private fun encodeBitFlags(flags: BooleanArray): Pair<ByteArray, Int> {
        var lastTrue = -1
        for (i in flags.indices) {
            if (flags[i]) lastTrue = i
        }
        if (lastTrue < 0) return ByteArray(1) to 0
        val byteCount = (lastTrue / 8) + 1
        val out = ByteArray(byteCount)
        for (i in 0..lastTrue) {
            if (flags[i]) {
                val byteIdx = i / 8
                val bitIdx = 7 - (i % 8)
                out[byteIdx] = (out[byteIdx].toInt() or (1 shl bitIdx)).toByte()
            }
        }
        val unused = (byteCount * 8) - (lastTrue + 1)
        return out to unused
    }

    private fun derExtension(oid: String, critical: Boolean, valueDer: ByteArray): ByteArray {
        val parts = mutableListOf(derOid(oid))
        if (critical) parts += derBoolean(true)
        parts += derOctetString(valueDer)
        return derSequence(*parts.toTypedArray())
    }

    private fun encodeTime(millis: Long): ByteArray {
        val utc = TimeZone.getTimeZone("UTC")
        val yearFmt = SimpleDateFormat("yyyy", Locale.US).apply { timeZone = utc }
        val year = yearFmt.format(Date(millis)).toInt()
        return if (year in 1950..2049) {
            val fmt = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply { timeZone = utc }
            derTag(0x17, fmt.format(Date(millis)).toByteArray(Charsets.US_ASCII))
        } else {
            val fmt = SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US).apply { timeZone = utc }
            derTag(0x18, fmt.format(Date(millis)).toByteArray(Charsets.US_ASCII))
        }
    }

    private fun isPrintableAscii(s: String): Boolean {
        return s.all { ch ->
            ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' ||
                ch in " '()+,-./:=?"
        }
    }

    private fun derSequence(vararg items: ByteArray): ByteArray = derTag(0x30, concat(*items))
    private fun derSet(vararg items: ByteArray): ByteArray = derTag(0x31, concat(*items))
    private fun derExplicitTag(tagNo: Int, inner: ByteArray): ByteArray = derTag(0xA0 or tagNo, inner)
    private fun derPrimitiveTag(tag: Int, content: ByteArray): ByteArray = derTag(tag, content)
    private fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)
    private fun derBoolean(v: Boolean): ByteArray = byteArrayOf(0x01, 0x01, if (v) 0xFF.toByte() else 0x00)
    private fun derOctetString(bytes: ByteArray): ByteArray = derTag(0x04, bytes)
    private fun derPrintableString(s: String): ByteArray = derTag(0x13, s.toByteArray(Charsets.US_ASCII))
    private fun derIa5String(s: String): ByteArray = derTag(0x16, s.toByteArray(Charsets.US_ASCII))
    private fun derUtf8String(s: String): ByteArray = derTag(0x0C, s.toByteArray(Charsets.UTF_8))

    private fun derInteger(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return derTag(0x02, bytes)
    }

    private fun derBitString(bytes: ByteArray, unusedBits: Int): ByteArray {
        val payload = ByteArray(bytes.size + 1)
        payload[0] = unusedBits.toByte()
        System.arraycopy(bytes, 0, payload, 1, bytes.size)
        return derTag(0x03, payload)
    }

    private fun derOid(oid: String): ByteArray {
        val arcs = oid.split('.').map { it.toLong() }
        require(arcs.size >= 2) { "Invalid OID: $oid" }
        val out = ByteArrayOutputStream()
        out.write(((arcs[0] * 40) + arcs[1]).toInt())
        for (i in 2 until arcs.size) {
            encodeBase128(out, arcs[i])
        }
        return derTag(0x06, out.toByteArray())
    }

    private fun encodeBase128(out: ByteArrayOutputStream, value: Long) {
        if (value < 0x80) {
            out.write(value.toInt())
            return
        }
        val stack = LongArray(10)
        var v = value
        var count = 0
        while (v > 0) {
            stack[count++] = v and 0x7F
            v = v ushr 7
        }
        for (i in count - 1 downTo 0) {
            val b = if (i > 0) (stack[i].toInt() or 0x80) else stack[i].toInt()
            out.write(b)
        }
    }

    private fun derTag(tag: Int, content: ByteArray): ByteArray {
        val lenBytes = encodeLength(content.size)
        val out = ByteArray(1 + lenBytes.size + content.size)
        out[0] = tag.toByte()
        System.arraycopy(lenBytes, 0, out, 1, lenBytes.size)
        System.arraycopy(content, 0, out, 1 + lenBytes.size, content.size)
        return out
    }

    private fun encodeLength(len: Int): ByteArray {
        if (len < 0x80) return byteArrayOf(len.toByte())
        val bytes = mutableListOf<Byte>()
        var v = len
        while (v > 0) {
            bytes.add(0, (v and 0xFF).toByte())
            v = v ushr 8
        }
        val out = ByteArray(1 + bytes.size)
        out[0] = (0x80 or bytes.size).toByte()
        bytes.forEachIndexed { idx, b -> out[idx + 1] = b }
        return out
    }

    private fun concat(vararg arrays: ByteArray): ByteArray {
        val total = arrays.sumOf { it.size }
        val out = ByteArray(total)
        var pos = 0
        arrays.forEach { arr ->
            System.arraycopy(arr, 0, out, pos, arr.size)
            pos += arr.size
        }
        return out
    }
}
