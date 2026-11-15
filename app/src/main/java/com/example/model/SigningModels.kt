package com.example.model

enum class MainTab {
    VERIFY,
    RESIGN,
    PARTITION
}

enum class AospKeyProfile(
    val id: String,
    val displayName: String,
    val commonName: String,
    val orgUnit: String,
    val organization: String,
    val email: String
) {
    TESTKEY(
        id = "aosp_testkey",
        displayName = "AOSP TestKey",
        commonName = "Android",
        orgUnit = "Android",
        organization = "Android",
        email = "android@android.com"
    ),
    PLATFORM(
        id = "aosp_platform",
        displayName = "AOSP Platform",
        commonName = "Android Platform",
        orgUnit = "Android",
        organization = "Android",
        email = "android@android.com"
    ),
    SHARED(
        id = "aosp_shared",
        displayName = "AOSP Shared",
        commonName = "Android Shared",
        orgUnit = "Android",
        organization = "Android",
        email = "android@android.com"
    ),
    MEDIA(
        id = "aosp_media",
        displayName = "AOSP Media",
        commonName = "Android Media",
        orgUnit = "Android",
        organization = "Android",
        email = "android@android.com"
    )
}

enum class KeyAlgorithmOption(
    val label: String,
    val jcaAlg: String,
    val keySizeBits: Int,
    val defaultSigAlg: String,
    val supportedSigAlgs: List<String>
) {
    RSA_2048(
        label = "RSA 2048",
        jcaAlg = "RSA",
        keySizeBits = 2048,
        defaultSigAlg = "SHA256withRSA",
        supportedSigAlgs = listOf("SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA1withRSA")
    ),
    RSA_4096(
        label = "RSA 4096",
        jcaAlg = "RSA",
        keySizeBits = 4096,
        defaultSigAlg = "SHA256withRSA",
        supportedSigAlgs = listOf("SHA256withRSA", "SHA384withRSA", "SHA512withRSA")
    ),
    EC_P256(
        label = "EC P-256",
        jcaAlg = "EC",
        keySizeBits = 256,
        defaultSigAlg = "SHA256withECDSA",
        supportedSigAlgs = listOf("SHA256withECDSA", "SHA384withECDSA")
    ),
    EC_P384(
        label = "EC P-384",
        jcaAlg = "EC",
        keySizeBits = 384,
        defaultSigAlg = "SHA384withECDSA",
        supportedSigAlgs = listOf("SHA384withECDSA", "SHA512withECDSA", "SHA256withECDSA")
    )
}

enum class KeyOrigin {
    CUSTOM,
    IMPORTED,
    KEY_UPDATER
}

data class CustomKeyCreationSpec(
    val alias: String = "signerlab_key",
    val password: String = "signerlab",
    val algorithm: KeyAlgorithmOption = KeyAlgorithmOption.RSA_2048,
    val sigAlgorithm: String = "SHA256withRSA",
    val validityYears: Int = 25,
    val commonName: String = "SignerLAB Developer",
    val orgUnit: String = "Mobile Security",
    val organization: String = "SignerLAB",
    val locality: String = "Paris",
    val state: String = "IDF",
    val country: String = "FR",
    val email: String = "",
    val saveToVault: Boolean = true
)

data class StoredKeyEntry(
    val id: String,
    val alias: String,
    val filePath: String,
    val origin: KeyOrigin,
    val keyAlgorithm: String,
    val keySizeBits: Int,
    val sigAlgName: String,
    val subjectDn: String,
    val serialNumberHex: String,
    val sha256: String,
    val notBeforeMs: Long,
    val notAfterMs: Long,
    val defaultPasswordHint: String? = null
)

data class RdnSlot(
    val key: String, // e.g. "E", "CN", "OU", "O", "L", "ST", "C"
    val value: String
)

data class ClonedKeySpec(
    val sourceApkPath: String,
    val sourceAppLabel: String,
    val sourceReport: ApkVerificationReport,
    val sourceCert: CertificateDetails,
    // Preserved structural & cryptographic logic
    val keyAlgorithm: String,
    val keySizeBits: Int,
    val sigAlgName: String,
    val x509Version: Int,
    val validityDays: Long,
    val orderedRdnSlots: List<RdnSlot>,
    val keyUsageBooleans: BooleanArray?,
    val extendedKeyUsageOids: List<String>,
    val basicConstraintsIsCa: Boolean,
    val basicConstraintsPathLen: Int?,
    val includeSki: Boolean,
    val includeAki: Boolean,
    // Editable new identity fields
    val newAlias: String,
    val newPassword: String,
    val newCommonName: String,
    val newOrgUnit: String,
    val newOrganization: String,
    val newLocality: String,
    val newState: String,
    val newCountry: String,
    val newEmail: String,
    val newSerialNumberDecimal: String,
    val newSerialNumberHex: String,
    val newValidityDays: Long,
    val signV1: Boolean,
    val signV2: Boolean,
    val signV3: Boolean,
    val signV4: Boolean
)

data class SigningOptions(
    val signV1: Boolean = true,
    val signV2: Boolean = true,
    val signV3: Boolean = true,
    val signV4: Boolean = false,
    val zipAlign4: Boolean = true
)

data class SignedApkResult(
    val sourceDisplayName: String,
    val sourcePath: String,
    val outputPath: String,
    val outputSizeBytes: Long,
    val appliedSchemes: List<SignatureSchemeType>,
    val signerName: String,
    val certSha256: String,
    val isZipAligned4: Boolean,
    val v4IdsigPath: String? = null,
    val verificationReport: ApkVerificationReport
)

sealed interface SigningUiState {
    data object Idle : SigningUiState
    data class AnalyzingTarget(val fileName: String) : SigningUiState
    data class Signing(
        val currentIndex: Int,
        val totalCount: Int,
        val currentFileName: String
    ) : SigningUiState
    data class Success(
        val results: List<SignedApkResult>,
        val signerLabel: String
    ) : SigningUiState
    data class Error(val message: String) : SigningUiState
}
