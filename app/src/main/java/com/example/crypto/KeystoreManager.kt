package com.example.crypto

import android.content.Context
import com.example.model.ClonedKeySpec
import com.example.model.CustomKeyCreationSpec
import com.example.model.KeyOrigin
import com.example.model.RdnSlot
import com.example.model.StoredKeyEntry
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.TimeUnit

class KeystoreManager(private val context: Context) {

    data class KeyMaterial(
        val privateKey: PrivateKey,
        val certificates: List<X509Certificate>,
        val displayName: String,
        val certSha256: String
    )

    private val vaultDir: File
        get() = File(context.filesDir, "key_vault").apply { mkdirs() }

    private val indexFile: File
        get() = File(vaultDir, "vault_index.json")

    fun listKeys(): List<StoredKeyEntry> {
        if (!indexFile.exists()) return emptyList()
        return try {
            val raw = indexFile.readText(Charsets.UTF_8)
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val obj = arr.getJSONObject(i)
                    val path = obj.getString("filePath")
                    if (!File(path).exists()) continue
                    add(
                        StoredKeyEntry(
                            id = obj.getString("id"),
                            alias = obj.getString("alias"),
                            filePath = path,
                            origin = KeyOrigin.valueOf(obj.optString("origin", KeyOrigin.CUSTOM.name)),
                            keyAlgorithm = obj.getString("keyAlgorithm"),
                            keySizeBits = obj.getInt("keySizeBits"),
                            sigAlgName = obj.getString("sigAlgName"),
                            subjectDn = obj.getString("subjectDn"),
                            serialNumberHex = obj.getString("serialNumberHex"),
                            sha256 = obj.getString("sha256"),
                            notBeforeMs = obj.getLong("notBeforeMs"),
                            notAfterMs = obj.getLong("notAfterMs"),
                            defaultPasswordHint = obj.optString("defaultPasswordHint").takeIf { it.isNotBlank() }
                        )
                    )
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun createCustomKey(spec: CustomKeyCreationSpec): Pair<StoredKeyEntry, KeyMaterial> {
        val cleanAlias = spec.alias.trim().ifBlank { "signerlab_key" }
        val password = spec.password.ifEmpty { "signerlab" }
        val keyPair = X509DerBuilder.generateKeyPair(spec.algorithm.jcaAlg, spec.algorithm.keySizeBits)
        val nowMs = System.currentTimeMillis()
        val afterMs = nowMs + TimeUnit.DAYS.toMillis(spec.validityYears.coerceIn(1, 100) * 365L)
        val serial = X509DerBuilder.generateRandomPositiveSerial()

        val rdns = buildList {
            if (spec.commonName.isNotBlank()) add(RdnSlot("CN", spec.commonName))
            if (spec.orgUnit.isNotBlank()) add(RdnSlot("OU", spec.orgUnit))
            if (spec.organization.isNotBlank()) add(RdnSlot("O", spec.organization))
            if (spec.locality.isNotBlank()) add(RdnSlot("L", spec.locality))
            if (spec.state.isNotBlank()) add(RdnSlot("ST", spec.state))
            if (spec.country.isNotBlank()) add(RdnSlot("C", spec.country))
            if (spec.email.isNotBlank()) add(RdnSlot("E", spec.email))
        }

        val cert = X509DerBuilder.buildSelfSignedCertificate(
            keyPair = keyPair,
            spec = X509DerBuilder.CertificateSpec(
                serialNumber = serial,
                notBeforeMs = nowMs,
                notAfterMs = afterMs,
                orderedRdns = rdns,
                sigAlgName = spec.sigAlgorithm
            )
        )

        val entry = persistKeyToVault(
            alias = cleanAlias,
            password = password,
            privateKey = keyPair.private,
            cert = cert,
            origin = KeyOrigin.CUSTOM,
            saveToIndex = spec.saveToVault
        )
        val sha = CryptoUtils.digestHex(cert.encoded, "SHA-256")
        return entry to KeyMaterial(keyPair.private, listOf(cert), cleanAlias, sha)
    }

    fun createAndSaveClonedKey(spec: ClonedKeySpec): Pair<StoredKeyEntry, KeyMaterial> {
        val cleanAlias = spec.newAlias.trim().ifBlank { "cloned_key" }
        val password = spec.newPassword.ifEmpty { "signerlab" }
        val (privateKey, cert) = KeyCloner.generateFromCloneSpec(spec)
        val entry = persistKeyToVault(
            alias = cleanAlias,
            password = password,
            privateKey = privateKey,
            cert = cert,
            origin = KeyOrigin.KEY_UPDATER,
            saveToIndex = true
        )
        val sha = CryptoUtils.digestHex(cert.encoded, "SHA-256")
        return entry to KeyMaterial(privateKey, listOf(cert), cleanAlias, sha)
    }

    fun inspectExternalKeystoreAliases(
        bytes: ByteArray,
        storePassword: String
    ): Pair<String, List<String>> {
        val types = listOf("PKCS12", "JKS", "BKS")
        var lastErr: Exception? = null
        for (type in types) {
            try {
                val ks = KeyStore.getInstance(type)
                ks.load(ByteArrayInputStream(bytes), storePassword.toCharArray())
                val aliases = ks.aliases().toList().filter { ks.isKeyEntry(it) }
                if (aliases.isNotEmpty()) {
                    return type to aliases
                }
            } catch (e: Exception) {
                lastErr = e
            }
        }
        throw IllegalStateException(lastErr?.message ?: "Cannot open keystore (wrong password or unsupported format)")
    }

    fun importExternalKeystore(
        bytes: ByteArray,
        storePassword: String,
        alias: String?,
        keyPassword: String
    ): StoredKeyEntry {
        val (ksType, aliases) = inspectExternalKeystoreAliases(bytes, storePassword)
        val targetAlias = alias?.takeIf { it in aliases } ?: aliases.first()
        val ks = KeyStore.getInstance(ksType)
        ks.load(ByteArrayInputStream(bytes), storePassword.toCharArray())

        val effectiveKeyPass = keyPassword.ifEmpty { storePassword }
        val key = ks.getKey(targetAlias, effectiveKeyPass.toCharArray()) as? PrivateKey
            ?: throw IllegalStateException("Cannot extract private key for alias '$targetAlias'")
        val cert = ks.getCertificate(targetAlias) as? X509Certificate
            ?: throw IllegalStateException("Missing X.509 certificate for alias '$targetAlias'")

        return persistKeyToVault(
            alias = targetAlias,
            password = effectiveKeyPass,
            privateKey = key,
            cert = cert,
            origin = KeyOrigin.IMPORTED,
            saveToIndex = true
        )
    }

    fun loadKeyMaterial(entry: StoredKeyEntry, password: String): KeyMaterial {
        val passChars = password.toCharArray()
        val ks = KeyStore.getInstance("PKCS12")
        FileInputStream(entry.filePath).use { ks.load(it, passChars) }
        val key = ks.getKey(entry.alias, passChars) as? PrivateKey
            ?: throw IllegalStateException("Invalid password or missing key '${entry.alias}'")
        val chain = ks.getCertificateChain(entry.alias)?.mapNotNull { it as? X509Certificate }
            ?: listOfNotNull(ks.getCertificate(entry.alias) as? X509Certificate)
        if (chain.isEmpty()) throw IllegalStateException("No certificate found for '${entry.alias}'")
        val sha = CryptoUtils.digestHex(chain.first().encoded, "SHA-256")
        return KeyMaterial(key, chain, entry.alias, sha)
    }

    fun exportVaultKeystore(entry: StoredKeyEntry, out: OutputStream) {
        FileInputStream(entry.filePath).use { input ->
            input.copyTo(out)
        }
    }

    fun deleteKey(id: String) {
        val current = listKeys()
        val target = current.firstOrNull { it.id == id }
        if (target != null) {
            File(target.filePath).delete()
        }
        saveIndex(current.filterNot { it.id == id })
    }

    private fun persistKeyToVault(
        alias: String,
        password: String,
        privateKey: PrivateKey,
        cert: X509Certificate,
        origin: KeyOrigin,
        saveToIndex: Boolean
    ): StoredKeyEntry {
        val id = UUID.randomUUID().toString().take(12)
        val file = if (saveToIndex) {
            File(vaultDir, "${id}.p12")
        } else {
            File(context.cacheDir, "ephemeral_${id}.p12")
        }

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        val passChars = password.toCharArray()
        ks.setKeyEntry(alias, privateKey, passChars, arrayOf(cert))
        FileOutputStream(file).use { ks.store(it, passChars) }

        val details = CryptoUtils.extractCertificateDetails(cert, 1, emptyList())
        val entry = StoredKeyEntry(
            id = id,
            alias = alias,
            filePath = file.absolutePath,
            origin = origin,
            keyAlgorithm = details.publicKeyAlgorithm,
            keySizeBits = details.publicKeySizeBits,
            sigAlgName = details.sigAlgName,
            subjectDn = details.subjectDn,
            serialNumberHex = details.serialNumberHex,
            sha256 = details.sha256,
            notBeforeMs = details.notBeforeMs,
            notAfterMs = details.notAfterMs,
            defaultPasswordHint = password
        )

        if (saveToIndex) {
            val updated = listOf(entry) + listKeys()
            saveIndex(updated)
        }
        return entry
    }

    private fun saveIndex(entries: List<StoredKeyEntry>) {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("id", e.id)
                    put("alias", e.alias)
                    put("filePath", e.filePath)
                    put("origin", e.origin.name)
                    put("keyAlgorithm", e.keyAlgorithm)
                    put("keySizeBits", e.keySizeBits)
                    put("sigAlgName", e.sigAlgName)
                    put("subjectDn", e.subjectDn)
                    put("serialNumberHex", e.serialNumberHex)
                    put("sha256", e.sha256)
                    put("notBeforeMs", e.notBeforeMs)
                    put("notAfterMs", e.notAfterMs)
                    e.defaultPasswordHint?.let { put("defaultPasswordHint", it) }
                }
            )
        }
        indexFile.writeText(arr.toString(2), Charsets.UTF_8)
    }
}
