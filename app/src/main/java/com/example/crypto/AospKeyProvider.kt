package com.example.crypto

import android.content.Context
import com.example.model.AospKeyProfile
import com.example.model.RdnSlot
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

class AospKeyProvider(private val context: Context) {

    data class LoadedAospKey(
        val profile: AospKeyProfile,
        val privateKey: PrivateKey,
        val certificate: X509Certificate,
        val certSha256: String
    )

    private val storeDir: File
        get() = File(context.filesDir, "aosp_keys").apply { mkdirs() }

    fun getAospKey(profile: AospKeyProfile): LoadedAospKey {
        val ksFile = File(storeDir, "${profile.id}.p12")
        val pass = "android".toCharArray()
        val alias = profile.id

        if (ksFile.exists()) {
            try {
                val ks = KeyStore.getInstance("PKCS12")
                FileInputStream(ksFile).use { ks.load(it, pass) }
                val key = ks.getKey(alias, pass) as? PrivateKey
                val cert = ks.getCertificate(alias) as? X509Certificate
                if (key != null && cert != null) {
                    return LoadedAospKey(
                        profile = profile,
                        privateKey = key,
                        certificate = cert,
                        certSha256 = CryptoUtils.digestHex(cert.encoded, "SHA-256")
                    )
                }
            } catch (_: Exception) {
                ksFile.delete()
            }
        }

        val keyPair = X509DerBuilder.generateKeyPair("RSA", 2048)
        val nowMs = System.currentTimeMillis()
        val afterMs = nowMs + TimeUnit.DAYS.toMillis(365L * 30L)
        val deterministicSerial = BigInteger(1, profile.id.toByteArray()).add(BigInteger.valueOf(0x936e91L))

        val rdns = listOf(
            RdnSlot("C", "US"),
            RdnSlot("ST", "California"),
            RdnSlot("L", "Mountain View"),
            RdnSlot("O", profile.organization),
            RdnSlot("OU", profile.orgUnit),
            RdnSlot("CN", profile.commonName),
            RdnSlot("E", profile.email)
        )

        val cert = X509DerBuilder.buildSelfSignedCertificate(
            keyPair = keyPair,
            spec = X509DerBuilder.CertificateSpec(
                serialNumber = deterministicSerial,
                notBeforeMs = nowMs,
                notAfterMs = afterMs,
                orderedRdns = rdns,
                sigAlgName = "SHA256withRSA",
                includeBasicConstraints = true,
                includeSki = true,
                includeAki = true
            )
        )

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry(alias, keyPair.private, pass, arrayOf(cert))
        FileOutputStream(ksFile).use { ks.store(it, pass) }

        return LoadedAospKey(
            profile = profile,
            privateKey = keyPair.private,
            certificate = cert,
            certSha256 = CryptoUtils.digestHex(cert.encoded, "SHA-256")
        )
    }
}
