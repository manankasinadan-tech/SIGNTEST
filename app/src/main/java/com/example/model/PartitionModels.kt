package com.example.model

enum class FileBrowserMode {
    APK_PICKER,
    DIRECTORY_PICKER
}

enum class XmlSignatureFormat(val label: String) {
    DER_HEX_LOWER("DER Hex (lower)"),
    DER_HEX_UPPER("DER Hex (UPPER)"),
    DER_BASE64("DER Base64"),
    SHA256_PLAIN_LOWER("SHA-256 (hex)"),
    SHA256_PLAIN_UPPER("SHA-256 (HEX)"),
    SHA256_COLON_LOWER("SHA-256 (aa:bb)"),
    SHA256_COLON_UPPER("SHA-256 (AA:BB)"),
    SHA1_PLAIN_LOWER("SHA-1 (hex)"),
    SHA1_PLAIN_UPPER("SHA-1 (HEX)"),
    SHA1_COLON_LOWER("SHA-1 (aa:bb)"),
    SHA1_COLON_UPPER("SHA-1 (AA:BB)"),
    SHA512_PLAIN_LOWER("SHA-512 (hex)"),
    SHA512_PLAIN_UPPER("SHA-512 (HEX)"),
    SHA512_COLON_LOWER("SHA-512 (aa:bb)"),
    SHA512_COLON_UPPER("SHA-512 (AA:BB)")
}

data class XmlSignatureReference(
    val id: String,
    val rawValue: String,
    val normalizedSha256: String?,
    val normalizedSha1: String?,
    val normalizedSha512: String?,
    val format: XmlSignatureFormat,
    val tagName: String,
    val attributeName: String?,
    val seinfo: String? = null,
    val associatedPackages: List<String> = emptyList(),
    val matchedGroupId: String? = null,
    val matchedGroupLabel: String? = null
)

data class XmlSignatureDocument(
    val path: String,
    val relativePath: String,
    val xmlKind: String,
    val viaRoot: Boolean,
    val references: List<XmlSignatureReference>,
    val snippet: String
)

data class PartitionApkEntry(
    val path: String,
    val relativePath: String,
    val partitionZone: String,
    val viaRoot: Boolean,
    val fileSizeBytes: Long,
    val report: ApkVerificationReport,
    val groupId: String,
    val schemeSummary: String,
    val hasV4Idsig: Boolean
)

data class SignatureGroup(
    val groupId: String,
    val index: Int,
    val displayName: String,
    val inferredRole: String,
    val certSha256: String,
    val subjectDn: String,
    val primaryCert: CertificateDetails?,
    val apks: List<PartitionApkEntry>,
    val matchedXmlPaths: List<String>,
    val seinfoValues: List<String>,
    val schemesUsed: List<SignatureSchemeType>
)

data class PartitionAuditReport(
    val rootPath: String,
    val viaRoot: Boolean,
    val totalApks: Int,
    val verifiedApks: Int,
    val skippedSymlinksCount: Int,
    val skippedSymlinkSamples: List<String>,
    val totalXmlScanned: Int,
    val xmlWithSignaturesCount: Int,
    val signatureGroups: List<SignatureGroup>,
    val apkEntries: List<PartitionApkEntry>,
    val xmlDocuments: List<XmlSignatureDocument>,
    val unmatchedXmlRefCount: Int,
    val isCoherent: Boolean,
    val coherenceNotes: List<String>,
    val auditedAtMs: Long
)

enum class PartitionKeyStrategyMode {
    AUTO_CLONE_PER_GROUP,
    AOSP_BY_ROLE,
    CUSTOM_VAULT
}

data class GroupKeyAssignment(
    val groupId: String,
    val groupDisplayName: String,
    val inferredRole: String,
    val apkCount: Int,
    val aospProfile: AospKeyProfile,
    val customKeyEntry: StoredKeyEntry? = null,
    val customKeyPassword: String = "signerlab"
)

data class PartitionResignPlan(
    val strategyMode: PartitionKeyStrategyMode = PartitionKeyStrategyMode.AUTO_CLONE_PER_GROUP,
    val groupAssignments: List<GroupKeyAssignment> = emptyList(),
    val zipAlign4: Boolean = true,
    val saveClonedKeysToVault: Boolean = true
)

data class GroupNewKeySummary(
    val groupDisplayName: String,
    val oldCertSha256: String,
    val newCertSha256: String,
    val keyLabel: String,
    val resignedCount: Int
)

data class PartitionResignResult(
    val rootPath: String,
    val strategyMode: PartitionKeyStrategyMode,
    val resignedApkCount: Int,
    val skippedSymlinksCount: Int,
    val updatedXmlFileCount: Int,
    val replacedXmlRefCount: Int,
    val groupKeySummaries: List<GroupNewKeySummary>,
    val postAuditReport: PartitionAuditReport,
    val errors: List<String>
)

sealed interface PartitionAuditUiState {
    data object Idle : PartitionAuditUiState
    data class Scanning(
        val phase: String,
        val current: Int,
        val total: Int,
        val currentItem: String
    ) : PartitionAuditUiState
    data class Verified(val report: PartitionAuditReport) : PartitionAuditUiState
    data class Error(val message: String) : PartitionAuditUiState
}

sealed interface PartitionResignUiState {
    data object Idle : PartitionResignUiState
    data class Resigning(
        val phase: String,
        val current: Int,
        val total: Int,
        val currentItem: String
    ) : PartitionResignUiState
    data class Success(val result: PartitionResignResult) : PartitionResignUiState
    data class Error(val message: String) : PartitionResignUiState
}
