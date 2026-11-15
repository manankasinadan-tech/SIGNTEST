package com.example

import com.example.api.DocumentationPdfGenerator
import com.example.api.SignerApiContract
import com.example.crypto.ApkSigningBlockInspector
import com.example.crypto.CryptoUtils
import com.example.crypto.ReportFormatter
import com.example.model.ApkVerificationReport
import com.example.model.AppLanguage
import com.example.model.SchemeVerificationDetail
import com.example.model.SignatureSchemeType
import com.example.model.SigningBlockInfo
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class CryptoAndReportTest {

    // Sample X.509 DER certificate (Base64 from Samsung Cert example)
    private val sampleCertBase64 =
        "MIIE1DCCA7ygAwIBAgIJANIJlaecDarWMA0GCSqGSIb3DQEBBQUAMIGiMQswCQYDVQQGEwJLUjEUMBIGA1UECBMLU291dGggS29yZWExEzARBgNVBAcTClN1d29uIENpdHkxHDAaBgNVBAoTE1NhbXN1bmcgQ29ycG9yYXRpb24xDDAKBgNVBAsTA0RNQzEVMBMGA1UEAxMMU2Ftc3VuZyBDZXJ0MSUwIwYJKoZIhvcNAQkBFhZhbmRyb2lkLm9zQHNhbXN1bmcuY29tMB4XDTExMDYyMjEyMjUxMloXDTM4MTEwNzEyMjUxMlowgaIxCzAJBgNVBAYTAktSMRQwEgYDVQQIEwtTb3V0aCBLb3JlYTETMBEGA1UEBxMKU3V3b24gQ2l0eTEcMBoGA1UEChMTU2Ftc3VuZyBDb3Jwb3JhdGlvbjEMMAoGA1UECxMDRE1DMRUwEwYDVQQDEwxTYW1zdW5nIENlcnQxJTAjBgkqhkiG9w0BCQEWFmFuZHJvaWQub3NAc2Ftc3VuZy5jb20wggEgMA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQDJhjhKPh8vsgZnDnjvIyIVwNJvRaInKNuZpE2hHDWsM6cf4HHEotaCWptMiLMz7ZbzxebGZtYPPulMSQiFq8+NxmD3B6q8d+rT4tDYrugQjBXNJg8uhQQsKNLyktqjxtoMe/I5HbeEGq3o/fDJ0N7893Ek5tLeCp4NLadGw2cOT/zchbcBu0dEhhuW/3MR2jYDxaEDNuVf+jS0NT7tyF9RAV4VGMZ+MJ45+HY5/xeBB/EJzRhBGmB38mlktuY/inC5YZ2wQwajI8Gh0jr4Z+GfFPVw/+Vz0OOgwrMGMqrsMXM4CZS+HjQeOpC9LkthVIH0bbOeqDgWRI7DX+sXNcHzAgEDo4IBCzCCAQcwHQYDVR0OBBYEFJMsOvcLYnoMdhC1oOdCfWz66j8eMIHXBgNVHSMEgc8wgcyAFJMsOvcLYnoMdhC1oOdCfWz66j8eoYGopIGlMIGiMQswCQYDVQQGEwJLUjEUMBIGA1UECBMLU291dGggS29yZWExEzARBgNVBAcTClN1d29uIENpdHkxHDAaBgNVBAoTE1NhbXN1bmcgQ29ycG9yYXRpb24xDDAKBgNVBAsTA0RNQzEVMBMGA1UEAxMMU2Ftc3VuZyBDZXJ0MSUwIwYJKoZIhvcNAQkBFhZhbmRyb2lkLm9zQHNhbXN1bmcuY29tggkA0gmVp5wNqtYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAMpYB/kDgNqSobMXUndjBtUFZmOcmN1OLDUMDaaxRUw9jqs6MAZoaZmFqLxuyxfq9bzEyYfOA40cWI/BT2ePFP1/W0ZZdewAOTcJEwbJ+L+mjI/8Hf1LEZ16GJHqoARhxN+MMm78BxWekKZ20vwslt9cQenuB7hAvcv9HlQFk4mdS4RTEL4udKkLnMIiX7GQOoZJO0Tq76dEgkSti9JJkk6htuUwLRvRMYWHVjC9kgWSJDFEt+yjULIVb9HDb7i2raWDK0E6B9xUl3tRs3Q81n5nEYNufAH2WzoO0shisLYLEjxJgjUaXM/BaM3VZRmnMv4pJVUTWxXAek2nAjIEBWA=="

    private fun decodeBase64(b64: String): ByteArray = java.util.Base64.getDecoder().decode(b64)

    @Test
    fun `extractCertificateDetails computes exact hashes crc32 colon fingerprints and known signer`() {
        val der = decodeBase64(sampleCertBase64)
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate

        val details = CryptoUtils.extractCertificateDetails(
            cert = cert,
            index = 1,
            schemeTags = listOf("V1", "V2", "V3")
        )

        assertEquals("X.509", details.type)
        assertEquals(3, details.version)
        assertEquals("15134792569865480918", details.serialNumberDecimal)
        assertTrue(details.isSelfSigned)
        assertEquals("0xb378e95c", details.hashCodeHex)
        assertEquals(-1283921572, details.hashCodeInt)
        assertEquals("6c4a50e5", details.crc32Hex)
        assertEquals(1816809701L, details.crc32Long)
        assertEquals("d087e72912fba064cafa78dc34aea839", details.md5)
        assertEquals("9ca5170f381919dfe0446fcdab18b19a143b3163", details.sha1)
        assertEquals(
            "9C:A5:17:0F:38:19:19:DF:E0:44:6F:CD:AB:18:B1:9A:14:3B:31:63",
            details.sha1Colon
        )
        assertEquals("2ad58c62454dd19c6c8c091c06fedd53ee6a0c3d24990d67d0727022", details.sha224)
        assertEquals("34df0e7a9f1cf1892e45c056b4973cd81ccf148a4050d11aea4ac5a65f900a42", details.sha256)
        assertTrue(details.sha256Colon.startsWith("34:DF:0E:7A:9F:1C:F1:89:"))
        assertEquals("Samsung Platform / OEM Cert", details.knownSignerHint)
        assertEquals(
            "315a510cd19c9591f620c34baba45312a72bacf203fb21fee5b3959a0a68a91cd3bb710abb6ba0e661bb549498814892",
            details.sha384
        )
        assertEquals(
            "0018b67dbb7cbe4ce3ed227c683e63738c491530c59ed76432b6172f78adb2fa98d50230f9d668cdda29e6b80a3718dbad001de679ed006a6087dc3ce0ed5782",
            details.sha512
        )
        assertEquals(sampleCertBase64, details.certBase64)
        assertTrue(details.signatureBase64.startsWith("AQAABNgwggTU"))
        assertTrue(details.publicKeySummary.startsWith("OpenSSLRSAPublicKey{modulus=c98638"))
        assertTrue(details.publicKeySummary.endsWith(",publicExponent=3}"))
    }

    @Test
    fun `reportFormatter outputs french and english plain text and valid json with apiVersion`() {
        val der = decodeBase64(sampleCertBase64)
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val details = CryptoUtils.extractCertificateDetails(cert, 1, listOf("V1", "V2", "V3"))

        val report = ApkVerificationReport(
            id = "test",
            appLabel = "Gestionnaire d'espace de stockage",
            packageName = "com.samsung.android.storagemanager",
            versionName = "16",
            versionCode = 36L,
            minSdk = 33,
            targetSdk = 36,
            isDebuggable = false,
            zipEntryCount = 1893,
            isZipAligned4 = true,
            filePath = "/storage/emulated/0/Recordings/StorageManager/StorageManager.apk",
            fileSizeBytes = 2_500_000L,
            apkSha256 = "abcd",
            apkSha1 = "123456",
            apkMd5 = "1234",
            apkCrc32Hex = "deadbeef",
            isVerified = true,
            detectedSchemes = listOf(SignatureSchemeType.V1, SignatureSchemeType.V2, SignatureSchemeType.V3),
            verifiedSchemes = listOf(SignatureSchemeType.V1, SignatureSchemeType.V2, SignatureSchemeType.V3),
            schemeDetails = listOf(
                SchemeVerificationDetail(
                    scheme = SignatureSchemeType.V2,
                    isPresent = true,
                    isVerified = true,
                    signerCount = 1,
                    signatureAlgorithms = listOf("RSA_PKCS1_V1_5_WITH_SHA256"),
                    digestAlgorithms = listOf("CHUNKED_SHA256")
                )
            ),
            certificates = listOf(details),
            v3Lineage = emptyList(),
            sourceStamp = null,
            v1JarDetails = null,
            signingBlockInfo = SigningBlockInfo(
                present = false,
                blockOffset = -1L,
                blockSizeBytes = 0L,
                pairs = emptyList(),
                v1Verified = true,
                v2Verified = true,
                v3Verified = true,
                v31Verified = false,
                v3MinSdk = null,
                v3MaxSdk = null,
                v31RotationMinSdk = null,
                v4IdsigFound = false,
                v4IdsigPath = null,
                v4Verified = false,
                contentDigestAlgorithms = emptyList()
            ),
            errors = emptyList(),
            warnings = emptyList(),
            verifiedAtMs = 1700000000000L
        )

        val frText = ReportFormatter.formatPlainText(report, AppLanguage.FR)
        assertTrue(frText.contains("Vérification de la signature: Gestionnaire d'espace de stockage v16 (36)"))
        assertTrue(frText.contains("Schéma de signature : V1 + V2 + V3"))
        assertTrue(frText.contains("CERTIFICAT №1"))
        assertTrue(frText.contains("Code de hachage : 0xb378e95c (-1283921572)"))

        val enText = ReportFormatter.formatPlainText(report, AppLanguage.EN)
        assertTrue(enText.contains("Signature verification: Gestionnaire d'espace de stockage v16 (36)"))
        assertTrue(enText.contains("CERTIFICATE #1"))

        val jsonStr = ReportFormatter.formatJson(listOf(report))
        val parsed = JSONObject(jsonStr)
        assertEquals("SignerLAB", parsed.getString("tool"))
        assertEquals("1.0", parsed.getString("apiVersion"))
        assertEquals(1, parsed.getInt("count"))
        val firstReport = parsed.getJSONArray("reports").getJSONObject(0)
        assertEquals(1, firstReport.getJSONArray("schemeMatrix").length())
        assertEquals("V2", firstReport.getJSONArray("schemeMatrix").getJSONObject(0).getString("scheme"))
    }

    @Test
    fun `inspectSigningBlock detects v2 and v3 pairs cleanly when EOCD is preceded by padding or data`() {
        // Synthetic layout:
        // [16 bytes dummy ZIP local data] + [APK Signing Block] + [dummy CD 46 bytes] + [EOCD 22 bytes]
        val pairValueSize = 4
        val pairTotalLen = 4L + pairValueSize // id (4) + value (4)
        val pairEntryBytes = 8 + 4 + pairValueSize // len (8) + id (4) + value (4)
        val sizeOfBlock = (pairEntryBytes * 2 + 8 + 16).toLong() // pairs + footerSize(8) + magic(16)
        val cdOffset = 16L + 8L + sizeOfBlock
        val cdSize = 46L

        val totalSize = (cdOffset + cdSize + 22).toInt()
        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)

        // 16 dummy bytes
        buf.position(16)
        // Block header size
        buf.putLong(sizeOfBlock)
        // Pair 1: V2 (0x7109871a)
        buf.putLong(pairTotalLen)
        buf.putInt(0x7109871a)
        buf.putInt(0x11223344)
        // Pair 2: V3 (0xf05368c0)
        buf.putLong(pairTotalLen)
        buf.putInt(0xf05368c0.toInt())
        buf.putInt(0x55667788)
        // Block footer size + magic
        buf.putLong(sizeOfBlock)
        buf.putLong(0x20676953204b5041L) // "APK Sig "
        buf.putLong(0x3234206b636f6c42L) // "Block 42"

        // Dummy CD entry (46 bytes)
        buf.putInt(0x02014b50)
        buf.position(buf.position() + 42)

        // EOCD (22 bytes)
        buf.putInt(0x06054b50)
        buf.putShort(0)
        buf.putShort(0)
        buf.putShort(1)
        buf.putShort(1)
        buf.putInt(cdSize.toInt())
        buf.putInt(cdOffset.toInt())
        buf.putShort(0)

        val tempFile = File.createTempFile("synthetic_apk_test", ".apk")
        try {
            tempFile.writeBytes(buf.array())
            val parsed = ApkSigningBlockInspector.inspectSigningBlock(tempFile)
            assertTrue(parsed.present)
            assertEquals(16L, parsed.blockOffset)
            assertEquals(2, parsed.pairs.size)
            assertEquals("0x7109871a", parsed.pairs[0].idHex)
            assertEquals("0xf05368c0", parsed.pairs[1].idHex)
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun `documentationPdfGenerator builds complete FR and EN API specs`() {
        val frDoc = DocumentationPdfGenerator.documentationPreviewText(AppLanguage.FR)
        assertTrue(frDoc.contains("Documentation API Inter-Application"))
        assertTrue(frDoc.contains(SignerApiContract.ACTION_VERIFY_APK))
        assertTrue(frDoc.contains(SignerApiContract.PROVIDER_URI))
        assertTrue(frDoc.contains("verify_apk"))
        assertTrue(frDoc.contains("result_json"))

        val enDoc = DocumentationPdfGenerator.documentationPreviewText(AppLanguage.EN)
        assertTrue(enDoc.contains("Inter-App Command API Documentation"))
        assertTrue(enDoc.contains(SignerApiContract.ACTION_VERIFY_APK))
        assertTrue(enDoc.contains(SignerApiContract.PROVIDER_URI))
        assertTrue(enDoc.contains("verify_apk"))
        assertTrue(enDoc.contains("result_json"))
    }

    @Test
    fun `signerApiContract constants remain stable`() {
        assertEquals("1.0", SignerApiContract.API_VERSION)
        assertEquals("com.aistudio.signerlab.action.VERIFY_APK", SignerApiContract.ACTION_VERIFY_APK)
        assertEquals("content://com.aistudio.signerlab.kxfmqt.api", SignerApiContract.PROVIDER_URI)
        assertEquals("verify_apk", SignerApiContract.METHOD_VERIFY_APK)
    }
}
