package com.example.crypto

import com.example.model.CertificateDetails
import com.example.model.ValidityStatus
import java.io.File
import java.io.FileInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Date
import java.util.zip.CRC32

object CryptoUtils {

    private const val BASE64_CHARS =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun encodeBase64(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val out = StringBuilder(((data.size + 2) / 3) * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            val hasB1 = i + 1 < data.size
            val hasB2 = i + 2 < data.size
            val b1 = if (hasB1) data[i + 1].toInt() and 0xFF else 0
            val b2 = if (hasB2) data[i + 2].toInt() and 0xFF else 0

            val triple = (b0 shl 16) or (b1 shl 8) or b2
            out.append(BASE64_CHARS[(triple ushr 18) and 0x3F])
            out.append(BASE64_CHARS[(triple ushr 12) and 0x3F])
            out.append(if (hasB1) BASE64_CHARS[(triple ushr 6) and 0x3F] else '=')
            out.append(if (hasB2) BASE64_CHARS[triple and 0x3F] else '=')
            i += 3
        }
        return out.toString()
    }

    fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4])
            sb.append("0123456789abcdef"[v and 0x0F])
        }
        return sb.toString()
    }

    fun digestHex(bytes: ByteArray, algorithm: String): String {
        return try {
            val md = MessageDigest.getInstance(algorithm)
            toHex(md.digest(bytes))
        } catch (_: Exception) {
            "N/A"
        }
    }

    fun computeCrc32(bytes: ByteArray): Pair<String, Long> {
        val crc = CRC32()
        crc.update(bytes)
        val value = crc.value
        return "%08x".format(value) to value
    }

    fun computeFileHashes(file: File): Triple<String, String, String> {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val md5 = MessageDigest.getInstance("MD5")
        val crc = CRC32()
        val buffer = ByteArray(64 * 1024)
        FileInputStream(file).use { input ->
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                sha256.update(buffer, 0, read)
                md5.update(buffer, 0, read)
                crc.update(buffer, 0, read)
            }
        }
        return Triple(toHex(sha256.digest()), toHex(md5.digest()), "%08x".format(crc.value))
    }

    fun buildAndroidSignatureBase64(certEncoded: ByteArray): String {
        val len = certEncoded.size
        val payload = ByteArray(5 + len)
        payload[0] = 0x01
        payload[1] = ((len ushr 24) and 0xFF).toByte()
        payload[2] = ((len ushr 16) and 0xFF).toByte()
        payload[3] = ((len ushr 8) and 0xFF).toByte()
        payload[4] = (len and 0xFF).toByte()
        System.arraycopy(certEncoded, 0, payload, 5, len)
        return encodeBase64(payload)
    }

    fun formatPublicKeySummary(key: PublicKey): Triple<String, String, Int> {
        return when (key) {
            is RSAPublicKey -> {
                val summary =
                    "OpenSSLRSAPublicKey{modulus=${key.modulus.toString(16)},publicExponent=${key.publicExponent.toString(16)}}"
                Triple(summary, "RSA", key.modulus.bitLength())
            }
            is ECPublicKey -> {
                val bits = key.params?.curve?.field?.fieldSize ?: 0
                val summary =
                    "ECPublicKey{bits=$bits,x=${key.w.affineX.toString(16)},y=${key.w.affineY.toString(16)}}"
                Triple(summary, "EC", bits)
            }
            is DSAPublicKey -> {
                val bits = key.params?.p?.bitLength() ?: 0
                val summary = "DSAPublicKey{bits=$bits,y=${key.y.toString(16)}}"
                Triple(summary, "DSA", bits)
            }
            else -> Triple(key.toString(), key.algorithm ?: "Unknown", key.encoded?.size?.times(8) ?: 0)
        }
    }

    fun extractCertificateDetails(
        cert: X509Certificate,
        index: Int,
        schemeTags: List<String>,
        nowMs: Long = System.currentTimeMillis()
    ): CertificateDetails {
        val encoded = cert.encoded
        val hashCodeInt = encoded.contentHashCode()
        val hashCodeHex = "0x%08x".format(hashCodeInt)
        val (crcHex, crcLong) = computeCrc32(encoded)

        val serialBigInt = cert.serialNumber
        val unsignedSerial = if (serialBigInt.signum() < 0) {
            BigInteger(1, serialBigInt.toByteArray())
        } else {
            serialBigInt
        }

        val subjectDn = cert.subjectX500Principal.name
        val issuerDn = cert.issuerX500Principal.name
        val isSelfSigned = cert.subjectX500Principal == cert.issuerX500Principal

        val notBeforeMs = cert.notBefore.time
        val notAfterMs = cert.notAfter.time
        val validityStatus = when {
            nowMs < notBeforeMs -> ValidityStatus.NOT_YET_VALID
            nowMs > notAfterMs -> ValidityStatus.EXPIRED
            else -> ValidityStatus.VALID
        }

        val (pubSummary, pubAlg, pubBits) = formatPublicKeySummary(cert.publicKey)
        val spkiSha256 = digestHex(cert.publicKey.encoded ?: ByteArray(0), "SHA-256")

        return CertificateDetails(
            index = index,
            schemeTags = schemeTags,
            type = cert.type ?: "X.509",
            version = cert.version,
            serialNumberDecimal = unsignedSerial.toString(),
            serialNumberHex = "0x" + unsignedSerial.toString(16),
            subjectDn = subjectDn,
            issuerDn = issuerDn,
            isSelfSigned = isSelfSigned,
            notBeforeMs = notBeforeMs,
            notAfterMs = notAfterMs,
            validityStatus = validityStatus,
            sigAlgName = cert.sigAlgName ?: "Unknown",
            sigAlgOid = cert.sigAlgOID ?: "",
            hashCodeHex = hashCodeHex,
            hashCodeInt = hashCodeInt,
            crc32Hex = crcHex,
            crc32Long = crcLong,
            md5 = digestHex(encoded, "MD5"),
            sha1 = digestHex(encoded, "SHA-1"),
            sha224 = digestHex(encoded, "SHA-224"),
            sha256 = digestHex(encoded, "SHA-256"),
            sha384 = digestHex(encoded, "SHA-384"),
            sha512 = digestHex(encoded, "SHA-512"),
            certBase64 = encodeBase64(encoded),
            signatureBitsHex = toHex(encoded),
            publicKeySummary = pubSummary,
            publicKeyAlgorithm = pubAlg,
            publicKeySizeBits = pubBits,
            publicKeySpkiSha256 = spkiSha256,
            signatureBase64 = buildAndroidSignatureBase64(encoded),
            keyUsage = extractKeyUsage(cert),
            extendedKeyUsage = extractExtendedKeyUsage(cert),
            basicConstraints = extractBasicConstraints(cert),
            subjectKeyIdentifier = extractExtensionHex(cert, "2.5.29.14"),
            authorityKeyIdentifier = extractExtensionHex(cert, "2.5.29.35")
        )
    }

    private fun extractKeyUsage(cert: X509Certificate): List<String> {
        val bits = cert.keyUsage ?: return emptyList()
        val names = listOf(
            "digitalSignature",
            "nonRepudiation",
            "keyEncipherment",
            "dataEncipherment",
            "keyAgreement",
            "keyCertSign",
            "cRLSign",
            "encipherOnly",
            "decipherOnly"
        )
        return bits.indices.filter { it < names.size && bits[it] }.map { names[it] }
    }

    private fun extractExtendedKeyUsage(cert: X509Certificate): List<String> {
        return try {
            cert.extendedKeyUsage ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun extractBasicConstraints(cert: X509Certificate): String? {
        val bc = cert.basicConstraints
        return when {
            bc == -1 -> "CA: false"
            bc == Int.MAX_VALUE -> "CA: true (unlimited path)"
            bc >= 0 -> "CA: true (pathLen=$bc)"
            else -> null
        }
    }

    private fun extractExtensionHex(cert: X509Certificate, oid: String): String? {
        val raw = cert.getExtensionValue(oid) ?: return null
        return toHex(raw)
    }

    fun isDateValid(notBeforeMs: Long, notAfterMs: Long, atMs: Long = System.currentTimeMillis()): Boolean {
        val d = Date(atMs)
        return !d.before(Date(notBeforeMs)) && !d.after(Date(notAfterMs))
    }
}
