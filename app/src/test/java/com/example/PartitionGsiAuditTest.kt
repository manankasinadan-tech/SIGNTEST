package com.example

import androidx.test.core.app.ApplicationProvider
import com.example.crypto.AospKeyProvider
import com.example.crypto.ApkReSigner
import com.example.crypto.CryptoUtils
import com.example.crypto.GsiChainOfTrustAnalyzer
import com.example.crypto.GsiPartitionReSigner
import com.example.crypto.XmlSignatureEngine
import com.example.model.AospKeyProfile
import com.example.model.PartitionKeyStrategyMode
import com.example.model.PartitionResignPlan
import com.example.model.SignatureSchemeType
import com.example.model.SigningOptions
import com.example.model.XmlSignatureFormat
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class PartitionGsiAuditTest {

    @Test
    fun `gsi analyzer and resigner preserve groups schemes xml formats and ignore symlinks without bak`() = runBlocking {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val aosp = AospKeyProvider(ctx)
        val platformKey = aosp.getAospKey(AospKeyProfile.PLATFORM)
        val mediaKey = aosp.getAospKey(AospKeyProfile.MEDIA)

        val sandbox = Files.createTempDirectory("signerlab_gsi_test").toFile()
        val gsiRoot = File(sandbox, "unpacked_gsi").apply { mkdirs() }
        val externalDir = File(sandbox, "external_host_phone").apply { mkdirs() }

        try {
            // External files pointed to by symlinks (must NEVER be scanned or modified)
            val externalApk = File(externalDir, "ExternalHostApp.apk")
            createSignedApkAt(
                ctx = ctx,
                targetFile = externalApk,
                packageName = "com.host.external",
                privateKey = platformKey.privateKey,
                cert = platformKey.certificate,
                options = SigningOptions(signV1 = true, signV2 = true, signV3 = true, signV4 = false)
            )
            val externalXml = File(externalDir, "host_mac.xml")
            val externalXmlOriginal = "<policy><signer signature=\"${CryptoUtils.toHex(platformKey.certificate.encoded)}\"/></policy>"
            externalXml.writeText(externalXmlOriginal, Charsets.UTF_8)
            val externalApkShaBefore = CryptoUtils.computeFileHashes(externalApk).sha256

            // Build GSI APK files
            val sysUiApk = File(gsiRoot, "system/priv-app/SystemUI/SystemUI.apk")
            val settingsApk = File(gsiRoot, "system/priv-app/Settings/Settings.apk")
            val mediaApk = File(gsiRoot, "system/app/MediaProvider/MediaProvider.apk")

            createSignedApkAt(
                ctx, sysUiApk, "com.android.systemui",
                platformKey.privateKey, platformKey.certificate,
                SigningOptions(signV1 = true, signV2 = true, signV3 = true, signV4 = false)
            )
            createSignedApkAt(
                ctx, settingsApk, "com.android.settings",
                platformKey.privateKey, platformKey.certificate,
                SigningOptions(signV1 = true, signV2 = true, signV3 = true, signV4 = false)
            )
            createSignedApkAt(
                ctx, mediaApk, "com.android.providers.media",
                mediaKey.privateKey, mediaKey.certificate,
                SigningOptions(signV1 = true, signV2 = true, signV3 = false, signV4 = false)
            )

            // Create symlinked APK and symlinked directory inside GSI root
            val symlinkApk = File(gsiRoot, "system/priv-app/LinkedExternal.apk")
            symlinkApk.parentFile?.mkdirs()
            Files.createSymbolicLink(symlinkApk.toPath(), externalApk.toPath())

            val symlinkDir = File(gsiRoot, "system/host_symlink_dir")
            Files.createSymbolicLink(symlinkDir.toPath(), externalDir.toPath())

            // Create multi-format XML files inside GSI root
            val platDetails = CryptoUtils.extractCertificateDetails(platformKey.certificate, 1, emptyList())
            val mediaDetails = CryptoUtils.extractCertificateDetails(mediaKey.certificate, 1, emptyList())

            val macXml = File(gsiRoot, "system/etc/selinux/plat_mac_permissions.xml").apply { parentFile?.mkdirs() }
            macXml.writeText(
                """
                <?xml version="1.0" encoding="utf-8"?>
                <policy>
                    <signer signature="${platDetails.signatureBitsHex.lowercase(Locale.US)}">
                        <seinfo value="platform"/>
                        <package name="com.android.systemui"/>
                    </signer>
                    <signer signature="${mediaDetails.signatureBitsHex.uppercase(Locale.US)}">
                        <seinfo value="media"/>
                    </signer>
                </policy>
                """.trimIndent(),
                Charsets.UTF_8
            )

            val knownSignerXml = File(gsiRoot, "system/etc/permissions/known_signer.xml").apply { parentFile?.mkdirs() }
            knownSignerXml.writeText(
                """
                <permissions>
                    <known-signer package="com.android.settings" certDigest="${platDetails.sha256Colon}" />
                </permissions>
                """.trimIndent(),
                Charsets.UTF_8
            )

            val base64Xml = File(gsiRoot, "system/etc/sysconfig/cert_base64.xml").apply { parentFile?.mkdirs() }
            base64Xml.writeText(
                """
                <config>
                    <cert value="${platDetails.certBase64}" />
                </config>
                """.trimIndent(),
                Charsets.UTF_8
            )

            // 1. Run GSI Chain-of-Trust Audit
            val analyzer = GsiChainOfTrustAnalyzer(ctx)
            val auditRes = analyzer.analyze(gsiRoot.absolutePath, useRoot = false)
            assertTrue("Audit failed: ${auditRes.exceptionOrNull()}", auditRes.isSuccess)
            val report = auditRes.getOrThrow()

            assertEquals(3, report.totalApks)
            assertEquals(3, report.verifiedApks)
            assertEquals(2, report.skippedSymlinksCount)
            assertEquals(2, report.signatureGroups.size)
            assertEquals(3, report.xmlWithSignaturesCount)
            assertEquals(0, report.unmatchedXmlRefCount)
            assertTrue("Initial audit should be coherent: ${report.coherenceNotes}", report.isCoherent)

            val groupPlat = report.signatureGroups.first { it.certSha256 == platDetails.sha256 }
            val groupMedia = report.signatureGroups.first { it.certSha256 == mediaDetails.sha256 }
            assertEquals(2, groupPlat.apks.size)
            assertEquals(1, groupMedia.apks.size)
            assertEquals("Platform", groupPlat.inferredRole)
            assertEquals("Media", groupMedia.inferredRole)
            assertTrue(groupPlat.seinfoValues.contains("platform"))
            assertTrue(groupMedia.seinfoValues.contains("media"))

            // 2. Run GSI Structure-Preserving Re-sign (AUTO_CLONE_PER_GROUP)
            val reSigner = GsiPartitionReSigner(ctx)
            val resignRes = reSigner.resignPartition(
                auditReport = report,
                plan = PartitionResignPlan(
                    strategyMode = PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP,
                    zipAlign4 = true,
                    saveClonedKeysToVault = false
                )
            )
            assertTrue("GSI resign failed: ${resignRes.exceptionOrNull()}", resignRes.isSuccess)
            val outcome = resignRes.getOrThrow()

            assertTrue("Errors encountered: ${outcome.errors}", outcome.errors.isEmpty())
            assertEquals(3, outcome.resignedApkCount)
            assertEquals(3, outcome.updatedXmlFileCount)
            assertEquals(4, outcome.replacedXmlRefCount)

            // Verify zero .bak files exist anywhere
            val bakFiles = gsiRoot.walkTopDown().filter { it.name.endsWith(".bak") }.toList()
            assertTrue("No .bak files allowed, found: $bakFiles", bakFiles.isEmpty())

            // Verify symlinks and external host files remained 100% untouched
            assertTrue(Files.isSymbolicLink(symlinkApk.toPath()))
            assertTrue(Files.isSymbolicLink(symlinkDir.toPath()))
            assertEquals(externalApkShaBefore, CryptoUtils.computeFileHashes(externalApk).sha256)
            assertEquals(externalXmlOriginal, externalXml.readText(Charsets.UTF_8))

            // Verify post-audit coherence & group preservation
            val post = outcome.postAuditReport
            assertEquals(3, post.totalApks)
            assertEquals(3, post.verifiedApks)
            assertEquals(2, post.signatureGroups.size)
            assertEquals(0, post.unmatchedXmlRefCount)
            assertTrue("Post-resign audit not coherent: ${post.coherenceNotes}", post.isCoherent)

            val newPlatGroup = post.signatureGroups.first { grp -> grp.apks.size == 2 }
            val newMediaGroup = post.signatureGroups.first { grp -> grp.apks.size == 1 }

            // New keys must differ from old keys AND differ between groups
            assertNotEquals(platDetails.sha256, newPlatGroup.certSha256)
            assertNotEquals(mediaDetails.sha256, newMediaGroup.certSha256)
            assertNotEquals(newPlatGroup.certSha256, newMediaGroup.certSha256)

            // Schemes per APK preserved: SystemUI/Settings V1+V2+V3, MediaProvider V1+V2 only
            val newSysUi = newPlatGroup.apks.first { it.relativePath.endsWith("SystemUI.apk") }
            assertTrue(newSysUi.report.verifiedSchemes.contains(SignatureSchemeType.V1))
            assertTrue(newSysUi.report.verifiedSchemes.contains(SignatureSchemeType.V2))
            assertTrue(newSysUi.report.verifiedSchemes.contains(SignatureSchemeType.V3))

            val newMedia = newMediaGroup.apks.first()
            assertTrue(newMedia.report.verifiedSchemes.contains(SignatureSchemeType.V1))
            assertTrue(newMedia.report.verifiedSchemes.contains(SignatureSchemeType.V2))
            assertFalse(newMedia.report.detectedSchemes.contains(SignatureSchemeType.V3))

            // Verify XML formats were preserved exactly!
            val updatedMacDoc = XmlSignatureEngine.parseXmlDocument(
                path = macXml.absolutePath,
                relativePath = "plat_mac_permissions.xml",
                rawText = macXml.readText(Charsets.UTF_8),
                viaRoot = false
            )!!
            assertEquals(XmlSignatureFormat.DER_HEX_LOWER, updatedMacDoc.references[0].format)
            assertEquals(newPlatGroup.certSha256, updatedMacDoc.references[0].normalizedSha256)
            assertEquals(XmlSignatureFormat.DER_HEX_UPPER, updatedMacDoc.references[1].format)
            assertEquals(newMediaGroup.certSha256, updatedMacDoc.references[1].normalizedSha256)

            val updatedKnownDoc = XmlSignatureEngine.parseXmlDocument(
                path = knownSignerXml.absolutePath,
                relativePath = "known_signer.xml",
                rawText = knownSignerXml.readText(Charsets.UTF_8),
                viaRoot = false
            )!!
            assertEquals(XmlSignatureFormat.SHA256_COLON_UPPER, updatedKnownDoc.references.first().format)
            assertEquals(newPlatGroup.certSha256, updatedKnownDoc.references.first().normalizedSha256)

            val updatedBase64Doc = XmlSignatureEngine.parseXmlDocument(
                path = base64Xml.absolutePath,
                relativePath = "cert_base64.xml",
                rawText = base64Xml.readText(Charsets.UTF_8),
                viaRoot = false
            )!!
            assertEquals(XmlSignatureFormat.DER_BASE64, updatedBase64Doc.references.first().format)
            assertEquals(newPlatGroup.certSha256, updatedBase64Doc.references.first().normalizedSha256)
        } finally {
            sandbox.deleteRecursively()
        }
    }

    private fun createSignedApkAt(
        ctx: android.content.Context,
        targetFile: File,
        packageName: String,
        privateKey: PrivateKey,
        cert: X509Certificate,
        options: SigningOptions
    ) {
        targetFile.parentFile?.mkdirs()
        val unsignedTmp = File.createTempFile("gsi_unsigned", ".apk")
        try {
            ZipOutputStream(FileOutputStream(unsignedTmp)).use { zos ->
                zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zos.write(buildMinimalBinaryManifest(packageName, 26))
                zos.closeEntry()

                val arscBytes = "ARSC_$packageName".toByteArray()
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
            }
            ApkReSigner(ctx).signApkToFile(
                readableInputApk = unsignedTmp,
                targetOutputApk = targetFile,
                targetOutputIdsig = null,
                privateKey = privateKey,
                certificates = listOf(cert),
                signerName = "TestSigner",
                options = options
            )
        } finally {
            unsignedTmp.delete()
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

        val resMapSize = 12
        val startNsSize = 24
        val manifestElemSize = 36 + 20
        val usesSdkElemSize = 36 + 20
        val endElemSize = 24
        val endNsSize = 24
        val totalSize = 8 + stringPoolSize + resMapSize + startNsSize +
            manifestElemSize + usesSdkElemSize + endElemSize + endElemSize + endNsSize

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003.toShort())
        buf.putShort(8.toShort())
        buf.putInt(totalSize)

        buf.putShort(0x0001.toShort())
        buf.putShort(stringPoolHeaderSize.toShort())
        buf.putInt(stringPoolSize)
        buf.putInt(strings.size)
        buf.putInt(0)
        buf.putInt(0x00000100)
        buf.putInt(stringsStart)
        buf.putInt(0)
        offsets.forEach { buf.putInt(it) }
        buf.put(stringBytes)

        buf.putShort(0x0180.toShort())
        buf.putShort(8.toShort())
        buf.putInt(resMapSize)
        buf.putInt(0x0101020c)

        buf.putShort(0x0100.toShort())
        buf.putShort(16.toShort())
        buf.putInt(startNsSize)
        buf.putInt(1)
        buf.putInt(-1)
        buf.putInt(2)
        buf.putInt(1)

        buf.putShort(0x0102.toShort())
        buf.putShort(16.toShort())
        buf.putInt(manifestElemSize)
        buf.putInt(1)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(3)
        buf.putShort(20.toShort())
        buf.putShort(20.toShort())
        buf.putShort(1.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putInt(-1)
        buf.putInt(4)
        buf.putInt(5)
        buf.putShort(8.toShort())
        buf.put(0.toByte())
        buf.put(0x03.toByte())
        buf.putInt(5)

        buf.putShort(0x0102.toShort())
        buf.putShort(16.toShort())
        buf.putInt(usesSdkElemSize)
        buf.putInt(2)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(6)
        buf.putShort(20.toShort())
        buf.putShort(20.toShort())
        buf.putShort(1.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putInt(1)
        buf.putInt(0)
        buf.putInt(-1)
        buf.putShort(8.toShort())
        buf.put(0.toByte())
        buf.put(0x10.toByte())
        buf.putInt(minSdk)

        buf.putShort(0x0103.toShort())
        buf.putShort(16.toShort())
        buf.putInt(endElemSize)
        buf.putInt(2)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(6)

        buf.putShort(0x0103.toShort())
        buf.putShort(16.toShort())
        buf.putInt(endElemSize)
        buf.putInt(3)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(3)

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
