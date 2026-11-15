package com.example.model

enum class AppLanguage(val code: String, val label: String) {
    FR("fr", "FR"),
    EN("en", "EN")
}

enum class RootStatus {
    UNKNOWN,
    CHECKING,
    GRANTED,
    DENIED,
    UNAVAILABLE
}

data class PermissionState(
    val hasStorageAccess: Boolean = false,
    val rootStatus: RootStatus = RootStatus.UNKNOWN,
    val rootIdentity: String? = null
)

enum class ApkSourceType {
    LOCAL_FILE,
    ROOT_FILE,
    CONTENT_URI
}

data class SelectedApkItem(
    val id: String,
    val displayName: String,
    val originalPath: String,
    val sourceType: ApkSourceType,
    val sizeBytes: Long,
    val lastModifiedMs: Long,
    val uriString: String? = null
)

data class FileEntry(
    val name: String,
    val path: String,
    val isDirectory: Boolean,
    val sizeBytes: Long,
    val lastModifiedMs: Long,
    val isReadable: Boolean,
    val viaRoot: Boolean
)

enum class SignatureSchemeType(val label: String) {
    V1("V1"),
    V2("V2"),
    V3("V3"),
    V3_1("V3.1"),
    V4("V4"),
    SOURCE_STAMP("SourceStamp")
}

enum class ValidityStatus {
    VALID,
    EXPIRED,
    NOT_YET_VALID
}

data class CertificateDetails(
    val index: Int,
    val schemeTags: List<String>,
    val type: String,
    val version: Int,
    val serialNumberDecimal: String,
    val serialNumberHex: String,
    val subjectDn: String,
    val issuerDn: String,
    val isSelfSigned: Boolean,
    val notBeforeMs: Long,
    val notAfterMs: Long,
    val validityStatus: ValidityStatus,
    val sigAlgName: String,
    val sigAlgOid: String,
    val hashCodeHex: String,
    val hashCodeInt: Int,
    val crc32Hex: String,
    val crc32Long: Long,
    val md5: String,
    val sha1: String,
    val sha224: String,
    val sha256: String,
    val sha384: String,
    val sha512: String,
    val certBase64: String,
    val signatureBitsHex: String,
    val publicKeySummary: String,
    val publicKeyAlgorithm: String,
    val publicKeySizeBits: Int,
    val publicKeySpkiSha256: String,
    val signatureBase64: String,
    val keyUsage: List<String>,
    val extendedKeyUsage: List<String>,
    val basicConstraints: String?,
    val subjectKeyIdentifier: String?,
    val authorityKeyIdentifier: String?
)

data class V3LineageNodeDetails(
    val index: Int,
    val certSha256: String,
    val subjectDn: String,
    val sigAlg: String,
    val flags: Int,
    val capabilities: List<String>
)

data class SourceStampDetails(
    val isPresent: Boolean,
    val isVerified: Boolean,
    val stampDigestSha256: String?,
    val timestampEpochSeconds: Long?,
    val certificate: CertificateDetails?,
    val errors: List<String>,
    val warnings: List<String>
)

data class V1JarDetails(
    val isVerified: Boolean,
    val signerFiles: List<String>,
    val sfFiles: List<String>,
    val digestAlgorithms: List<String>,
    val signedEntryCount: Int,
    val totalJarEntryCount: Int
)

data class SigningBlockPairInfo(
    val idHex: String,
    val name: String,
    val sizeBytes: Int
)

data class SigningBlockInfo(
    val present: Boolean,
    val blockOffset: Long,
    val blockSizeBytes: Long,
    val pairs: List<SigningBlockPairInfo>,
    val v2Verified: Boolean,
    val v3Verified: Boolean,
    val v31Verified: Boolean,
    val v3MinSdk: Int?,
    val v3MaxSdk: Int?,
    val v31RotationMinSdk: Int?,
    val v4IdsigFound: Boolean,
    val v4IdsigPath: String?,
    val v4Verified: Boolean,
    val contentDigestAlgorithms: List<String>
)

data class ApkVerificationReport(
    val id: String,
    val appLabel: String,
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long?,
    val minSdk: Int?,
    val targetSdk: Int?,
    val filePath: String,
    val fileSizeBytes: Long,
    val apkSha256: String,
    val apkMd5: String,
    val apkCrc32Hex: String,
    val isVerified: Boolean,
    val detectedSchemes: List<SignatureSchemeType>,
    val verifiedSchemes: List<SignatureSchemeType>,
    val certificates: List<CertificateDetails>,
    val v3Lineage: List<V3LineageNodeDetails>,
    val sourceStamp: SourceStampDetails?,
    val v1JarDetails: V1JarDetails?,
    val signingBlockInfo: SigningBlockInfo,
    val errors: List<String>,
    val warnings: List<String>,
    val verifiedAtMs: Long
)

sealed interface VerificationUiState {
    data object Idle : VerificationUiState
    data class Analyzing(
        val currentIndex: Int,
        val totalCount: Int,
        val currentFileName: String
    ) : VerificationUiState
    data class Success(
        val reports: List<ApkVerificationReport>,
        val selectedReportIndex: Int = 0
    ) : VerificationUiState
    data class Error(val message: String) : VerificationUiState
}
