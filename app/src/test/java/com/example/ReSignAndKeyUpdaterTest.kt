package com.example

import androidx.test.core.app.ApplicationProvider
import com.example.crypto.AospKeyProvider
import com.example.crypto.ApkReSigner
import com.example.crypto.CryptoUtils
import com.example.crypto.KeyCloner
import com.example.crypto.KeystoreManager
import com.example.crypto.X509DerBuilder
import com.example.model.AospKeyProfile
import com.example.model.ApkVerificationReport
import com.example.model.CustomKeyCreationSpec
import com.example.model.KeyAlgorithmOption
import com.example.model.RdnSlot
import com.example.model.SignatureSchemeType
import com.example.model.SigningBlockInfo
import com.example.model.SigningOptions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ReSignAndKeyUpdaterTest {

    private val samsungCertBase64 =
        "MIIE1DCCA7ygAwIBAgIJANIJlaecDarWMA0GCSqGSIb3DQEBBQUAMIGiMQswCQYDVQQGEwJLUjEUMBIGA1UECBMLU291dGggS29yZWExEzARBgNVBAcTClN1d29uIENpdHkxHDAaBgNVBAoTE1NhbXN1bmcgQ29ycG9yYXRpb24xDDAKBgNVBAsTA0RNQzEVMBMGA1UEAxMMU2Ftc3VuZyBDZXJ0MSUwIwYJKoZIhvcNAQkBFhZhbmRyb2lkLm9zQHNhbXN1bmcuY29tMB4XDTExMDYyMjEyMjUxMloXDTM4MTEwNzEyMjUxMlowgaIxCzAJBgNVBAYTAktSMRQwEgYDVQQIEwtTb3V0aCBLb3JlYTETMBEGA1UEBxMKU3V3b24gQ2l0eTEcMBoGA1UEChMTU2Ftc3VuZyBDb3Jwb3JhdGlvbjEMMAoGA1UECxMDRE1DMRUwEwYDVQQDEwxTYW1zdW5nIENlcnQxJTAjBgkqhkiG9w0BCQEWFmFuZHJvaWQub3NAc2Ftc3VuZy5jb20wggEgMA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQDJhjhKPh8vsgZnDnjvIyIVwNJvRaInKNuZpE2hHDWsM6cf4HHEotaCWptMiLMz7ZbzxebGZtYPPulMSQiFq8+NxmD3B6q8d+rT4tDYrugQjBXNJg8uhQQsKNLyktqjxtoMe/I5HbeEGq3o/fDJ0N7893Ek5tLeCp4NLadGw2cOT/zchbcBu0dEhhuW/3MR2jYDxaEDNuVf+jS0NT7tyF9RAV4VGMZ+MJ45+HY5/xeBB/EJzRhBGmB38mlktuY/inC5YZ2wQwajI8Gh0jr4Z+GfFPVw/+Vz0OOgwrMGMqrsMXM4CZS+HjQeOpC9LkthVIH0bbOeqDgWRI7DX+sXNcHzAgEDo4IBCzCCAQcwHQYDVR0OBBYEFJMsOvcLYnoMdhC1oOdCfWz66j8eMIHXBgNVHSMEgc8wgcyAFJMsOvcLYnoMdhC1oOdCfWz66j8eoYGopIGlMIGiMQswCQYDVQQGEwJLUjEUMBIGA1UECBMLU291dGggS29yZWExEzARBgNVBAcTClN1d29uIENpdHkxHDAaBgNVBAoTE1NhbXN1bmcgQ29ycG9yYXRpb24xDDAKBgNVBAsTA0RNQzEVMBMGA1UEAxMMU2Ftc3VuZyBDZXJ0MSUwIwYJKoZIhvcNAQkBFhZhbmRyb2lkLm9zQHNhbXN1bmcuY29tggkA0gmVp5wNqtYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAMpYB/kDgNqSobMXUndjBtUFZmOcmN1OLDUMDaaxRUw9jqs6MAZoaZmFqLxuyxfq9bzEyYfOA40cWI/BT2ePFP1/W0ZZdewAOTcJEwbJ+L+mjI/8Hf1LEZ16GJHqoARhxN+MMm78BxWekKZ20vwslt9cQenuB7hAvcv9HlQFk4mdS4RTEL4udKkLnMIiX7GQOoZJO0Tq76dEgkSti9JJkk6htuUwLRvRMYWHVjC9kgWSJDFEt+yjULIVb9HDb7i2raWDK0E6B9xUl3tRs3Q81n5nEYNufAH2WzoO0shisLYLEjxJgjUaXM/BaM3VZRmnMv4pJVUTWxXAek2nAjIEBWA=="

    @Test
    fun `x509DerBuilder creates valid self-signed RSA and EC certificates`() {
        val rsaPair = X509DerBuilder.generateKeyPair("RSA", 2048)
        val now = System.currentTimeMillis()
        val rsaCert = X509DerBuilder.buildSelfSignedCertificate(
            keyPair = rsaPair,
            spec = X509DerBuilder.CertificateSpec(
                serialNumber = BigInteger.valueOf(987654321L),
                notBeforeMs = now,
                notAfterMs = now + TimeUnit.DAYS.toMillis(365L * 25L),
                orderedRdns = listOf(
                    RdnSlot("CN", "SignerLAB Test"),
                    RdnSlot("O", "SignerLAB"),
                    RdnSlot("C", "FR")
                ),
                sigAlgName = "SHA256withRSA"
            )
        )
        rsaCert.verify(rsaPair.public)
        assertEquals(3, rsaCert.version)
        assertEquals("SHA256withRSA", rsaCert.sigAlgName)
        assertTrue(rsaCert.subjectX500Principal.name.contains("CN=SignerLAB Test"))

        val ecPair = X509DerBuilder.generateKeyPair("EC", 256)
        val ecCert = X509DerBuilder.buildSelfSignedCertificate(
            keyPair = ecPair,
            spec = X509DerBuilder.CertificateSpec(
                serialNumber = X509DerBuilder.generateRandomPositiveSerial(),
                notBeforeMs = now,
                notAfterMs = now + TimeUnit.DAYS.toMillis(365L * 10L),
                orderedRdns = listOf(RdnSlot("CN", "SignerLAB EC")),
                sigAlgName = "SHA256withECDSA"
            )
        )
        ecCert.verify(ecPair.public)
        assertEquals("SHA256withECDSA", ecCert.sigAlgName)
    }

    @Test
    fun `keyCloner decodes target structure and generates quasi-identical cert with new identity`() {
        val der = java.util.Base64.getDecoder().decode(samsungCertBase64)
        val sourceCert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val sourceDetails = CryptoUtils.extractCertificateDetails(
            cert = sourceCert,
            index = 1,
            schemeTags = listOf("V1", "V2", "V3")
        )

        val dummyReport = ApkVerificationReport(
            id = "src",
            appLabel = "StorageManager",
            packageName = "com.android.storagemanager",
            versionName = "16",
            versionCode = 36L,
            minSdk = 33,
            targetSdk = 36,
            isDebuggable = false,
            zipEntryCount = 100,
            isZipAligned4 = true,
            filePath = "/tmp/StorageManager.apk",
            fileSizeBytes = 1024L,
            apkSha256 = "00",
            apkSha1 = "00",
            apkMd5 = "00",
            apkCrc32Hex = "00",
            isVerified = true,
            detectedSchemes = listOf(SignatureSchemeType.V1, SignatureSchemeType.V2, SignatureSchemeType.V3),
            verifiedSchemes = listOf(SignatureSchemeType.V1, SignatureSchemeType.V2, SignatureSchemeType.V3),
            schemeDetails = emptyList(),
            certificates = listOf(sourceDetails),
            v3Lineage = emptyList(),
            sourceStamp = null,
            v1JarDetails = null,
            signingBlockInfo = SigningBlockInfo(
                present = true,
                blockOffset = 0L,
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

        val cloneSpec = KeyCloner.buildCloneSpecFromReport(dummyReport)
        // Verifies hex-encoded email OID decoding (#1616...)
        assertEquals("android.os@samsung.com", cloneSpec.newEmail)
        assertEquals("RSA", cloneSpec.keyAlgorithm)
        assertEquals(2048, cloneSpec.keySizeBits)
        assertEquals("SHA1withRSA", cloneSpec.sigAlgName)
        assertEquals("Samsung Corporation", cloneSpec.newOrganization)
        assertEquals("KR", cloneSpec.newCountry)

        val editedSpec = cloneSpec.copy(newCommonName = "Custom Mirror Cert")
        val (newKey, newCert) = KeyCloner.generateFromCloneSpec(editedSpec)
        val newDetails = CryptoUtils.extractCertificateDetails(newCert, 1, listOf("V1", "V2", "V3"))

        // Same structural & cryptographic logic
        assertEquals(sourceDetails.publicKeyAlgorithm, newDetails.publicKeyAlgorithm)
        assertEquals(sourceDetails.publicKeySizeBits, newDetails.publicKeySizeBits)
        assertEquals(sourceDetails.sigAlgName, newDetails.sigAlgName)
        assertEquals(sourceDetails.version, newDetails.version)
        assertEquals(sourceDetails.basicConstraints, newDetails.basicConstraints)

        // Fresh identity
        assertNotEquals(sourceDetails.sha256, newDetails.sha256)
        assertNotEquals(sourceDetails.serialNumberDecimal, newDetails.serialNumberDecimal)
        assertTrue(newDetails.subjectDn.contains("CN=Custom Mirror Cert"))
        assertTrue(newKey.encoded.isNotEmpty())
    }

    @Test
    fun `keystoreManager creates reloads exports and deletes custom p12 keys`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val manager = KeystoreManager(ctx)

        val (entry, _) = manager.createCustomKey(
            CustomKeyCreationSpec(
                alias = "unit_test_alias",
                password = "secret_pw",
                algorithm = KeyAlgorithmOption.RSA_2048,
                sigAlgorithm = "SHA256withRSA",
                validityYears = 10,
                commonName = "Unit Tester",
                saveToVault = true
            )
        )

        assertTrue(manager.listKeys().any { it.id == entry.id })
        val loaded = manager.loadKeyMaterial(entry, "secret_pw")
        assertEquals(entry.sha256, loaded.certSha256)

        val exportedOut = ByteArrayOutputStream()
        manager.exportVaultKeystore(entry, exportedOut)
        assertTrue(exportedOut.size() > 500)

        manager.deleteKey(entry.id)
        assertTrue(manager.listKeys().none { it.id == entry.id })
    }

    @Test
    fun `apkReSigner strips old META-INF aligns zip and signs V1 V2 V3 verified by ApkSignatureAnalyzer`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val aospProvider = AospKeyProvider(ctx)
        val aospKey = aospProvider.getAospKey(AospKeyProfile.TESTKEY)

        val inputApk = File.createTempFile("unsigned_input", ".apk")
        var outputApk: File? = null
        try {
            // Create minimal synthetic APK with valid binary AndroidManifest.xml, dummy old META-INF signature, and STORED resource
            ZipOutputStream(FileOutputStream(inputApk)).use { zos ->
                // Old signature file that must be stripped
                zos.putNextEntry(ZipEntry("META-INF/OLD.RSA"))
                zos.write("OLD_SIG".toByteArray())
                zos.closeEntry()

                val manifestBytes = buildMinimalBinaryManifest(
                    packageName = "com.example.sample",
                    minSdk = 24
                )
                zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zos.write(manifestBytes)
                zos.closeEntry()

                val arscBytes = "ARSC_PAYLOAD_DATA".toByteArray()
                val crc = CRC32().apply { update(arscBytes) }.value
                val stored = ZipEntry("resources.arsc").apply {
                    method = ZipEntry.STORED
                    size = arscBytes.size.toLong()
                    compressedSize = arscBytes.size.toLong()
                    this.crc = crc
                }
                zos.putNextEntry(stored)
                zos.write(arscBytes)
                zos.closeEntry()

                zos.putNextEntry(ZipEntry("classes.dex"))
                zos.write("DEX_PAYLOAD".toByteArray())
                zos.closeEntry()
            }

            val reSigner = ApkReSigner(ctx)
            val result = reSigner.resignApk(
                readableInputApk = inputApk,
                sourceDisplayPath = inputApk.absolutePath,
                sourceDisplayName = "sample_app.apk",
                isSourceWritableLocal = true,
                privateKey = aospKey.privateKey,
                certificates = listOf(aospKey.certificate),
                signerName = AospKeyProfile.TESTKEY.displayName,
                options = SigningOptions(
                    signV1 = true,
                    signV2 = true,
                    signV3 = true,
                    signV4 = false,
                    zipAlign4 = true
                )
            )
            outputApk = File(result.outputPath)

            val rpt = result.verificationReport
            val diag = "detected=${rpt.detectedSchemes}, verified=${rpt.verifiedSchemes}, v1=${rpt.v1JarDetails}, errors=${rpt.errors}, warnings=${rpt.warnings}"
            assertTrue("Output file missing", outputApk.exists())
            assertTrue("Missing -signed.apk suffix", outputApk.name.endsWith("-signed.apk"))
            assertTrue("Not 4B zipaligned: $diag", result.isZipAligned4)
            assertTrue("Report not verified: $diag", rpt.isVerified)
            assertTrue("V1 not verified: $diag", rpt.verifiedSchemes.contains(SignatureSchemeType.V1))
            assertTrue("V2 not verified: $diag", rpt.verifiedSchemes.contains(SignatureSchemeType.V2))
            assertTrue("V3 not verified: $diag", rpt.verifiedSchemes.contains(SignatureSchemeType.V3))
            assertEquals(aospKey.certSha256, rpt.certificates.first().sha256)

            ZipFile(outputApk).use { zip ->
                assertEquals(null, zip.getEntry("META-INF/OLD.RSA"))
            }
        } finally {
            inputApk.delete()
            outputApk?.delete()
        }
    }

    private fun buildMinimalBinaryManifest(packageName: String, minSdk: Int): ByteArray {
        val strings = listOf(
            "minSdkVersion",
            "http://schemas.android.com/apk/res/android",
            "android",
            "manifest",
            "package",
            packageName,
            "uses-sdk"
        )
        val rawStrings = ByteArrayOutputStream()
        val offsets = IntArray(strings.size)
        strings.forEachIndexed { idx, s ->
            offsets[idx] = rawStrings.size()
            val utf8 = s.toByteArray(Charsets.UTF_8)
            rawStrings.write(s.length)
            rawStrings.write(utf8.size)
            rawStrings.write(utf8)
            rawStrings.write(0)
        }
        while (rawStrings.size() % 4 != 0) {
            rawStrings.write(0)
        }
        val stringBytes = rawStrings.toByteArray()
        val stringPoolHeaderSize = 28
        val stringsStart = stringPoolHeaderSize + strings.size * 4
        val stringPoolSize = stringsStart + stringBytes.size

        val resMapSize = 12 // 8-byte header + 1 resource id (minSdkVersion)
        val startNsSize = 24
        val manifestElemSize = 36 + 20 // 1 attribute
        val usesSdkElemSize = 36 + 20 // 1 attribute
        val endElemSize = 24
        val endNsSize = 24
        val totalSize = 8 + stringPoolSize + resMapSize + startNsSize +
            manifestElemSize + usesSdkElemSize + endElemSize + endElemSize + endNsSize

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        // RES_XML_TYPE
        buf.putShort(0x0003.toShort())
        buf.putShort(8.toShort())
        buf.putInt(totalSize)

        // RES_STRING_POOL_TYPE (UTF-8)
        buf.putShort(0x0001.toShort())
        buf.putShort(stringPoolHeaderSize.toShort())
        buf.putInt(stringPoolSize)
        buf.putInt(strings.size)
        buf.putInt(0) // styleCount
        buf.putInt(0x00000100) // UTF8_FLAG
        buf.putInt(stringsStart)
        buf.putInt(0) // stylesStart
        offsets.forEach { buf.putInt(it) }
        buf.put(stringBytes)

        // RES_XML_RESOURCE_MAP_TYPE
        buf.putShort(0x0180.toShort())
        buf.putShort(8.toShort())
        buf.putInt(resMapSize)
        buf.putInt(0x0101020c) // android.R.attr.minSdkVersion

        // START_NAMESPACE
        buf.putShort(0x0100.toShort())
        buf.putShort(16.toShort())
        buf.putInt(startNsSize)
        buf.putInt(1)
        buf.putInt(-1)
        buf.putInt(2) // prefix: "android"
        buf.putInt(1) // uri

        // START_ELEMENT <manifest package="...">
        buf.putShort(0x0102.toShort())
        buf.putShort(16.toShort())
        buf.putInt(manifestElemSize)
        buf.putInt(1)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(3) // "manifest"
        buf.putShort(20.toShort())
        buf.putShort(20.toShort())
        buf.putShort(1.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        // attr: package
        buf.putInt(-1)
        buf.putInt(4) // "package"
        buf.putInt(5)
        buf.putShort(8.toShort())
        buf.put(0.toByte())
        buf.put(0x03.toByte()) // TYPE_STRING
        buf.putInt(5)

        // START_ELEMENT <uses-sdk android:minSdkVersion="minSdk">
        buf.putShort(0x0102.toShort())
        buf.putShort(16.toShort())
        buf.putInt(usesSdkElemSize)
        buf.putInt(2)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(6) // "uses-sdk"
        buf.putShort(20.toShort())
        buf.putShort(20.toShort())
        buf.putShort(1.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        // attr: android:minSdkVersion
        buf.putInt(1)
        buf.putInt(0) // "minSdkVersion"
        buf.putInt(-1)
        buf.putShort(8.toShort())
        buf.put(0.toByte())
        buf.put(0x10.toByte()) // TYPE_INT_DEC
        buf.putInt(minSdk)

        // END_ELEMENT </uses-sdk>
        buf.putShort(0x0103.toShort())
        buf.putShort(16.toShort())
        buf.putInt(endElemSize)
        buf.putInt(2)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(6)

        // END_ELEMENT </manifest>
        buf.putShort(0x0103.toShort())
        buf.putShort(16.toShort())
        buf.putInt(endElemSize)
        buf.putInt(3)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(3)

        // END_NAMESPACE
        buf.putShort(0x0101.toShort())
        buf.putShort(16.toShort())
        buf.putInt(endNsSize)
        buf.putInt(3)
        buf.putInt(-1)
        buf.putInt(2)
        buf.putInt(1)

        return buf.array()
    }
}
