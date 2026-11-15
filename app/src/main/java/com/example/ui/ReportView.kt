package com.example.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.crypto.ReportFormatter
import com.example.model.ApkVerificationReport
import com.example.model.AppLanguage
import com.example.model.CertificateDetails
import com.example.model.ValidityStatus
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.LocalSemanticColors

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ReportResultSection(
    reports: List<ApkVerificationReport>,
    selectedIndex: Int,
    language: AppLanguage,
    strings: UiStrings,
    onSelectReport: (Int) -> Unit,
    onCopyText: (String) -> Unit,
    onExportTxt: () -> Unit,
    onExportJson: () -> Unit,
    modifier: Modifier = Modifier
) {
    if (reports.isEmpty()) return
    val safeIndex = selectedIndex.coerceIn(0, reports.lastIndex)
    val report = reports[safeIndex]
    var rawMode by rememberSaveable { mutableStateOf(false) }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (reports.size > 1) {
            ScrollableTabRow(
                selectedTabIndex = safeIndex,
                edgePadding = 0.dp,
                containerColor = Color.Transparent,
                divider = {}
            ) {
                reports.forEachIndexed { idx, item ->
                    Tab(
                        selected = idx == safeIndex,
                        onClick = { onSelectReport(idx) },
                        text = {
                            Text(
                                text = item.appLabel,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    )
                }
            }
        }

        // View mode toggle + non-wrapping Export action bar
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = !rawMode,
                    onClick = { rawMode = false },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                    modifier = Modifier.testTag("mode_structured_button")
                ) {
                    Text(strings.viewStructured, maxLines = 1, softWrap = false)
                }
                SegmentedButton(
                    selected = rawMode,
                    onClick = { rawMode = true },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                    modifier = Modifier.testTag("mode_raw_button")
                ) {
                    Text(strings.viewRawReport, maxLines = 1, softWrap = false)
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val rawText = remember(report, language) {
                    ReportFormatter.formatPlainText(report, language)
                }
                OutlinedButton(
                    onClick = { onCopyText(rawText) },
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    modifier = Modifier
                        .weight(1f)
                        .minimumInteractiveComponentSize()
                        .testTag("copy_report_button")
                ) {
                    Icon(Icons.Filled.ContentCopy, null, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(strings.copyReport, maxLines = 1, softWrap = false)
                }
                OutlinedButton(
                    onClick = onExportTxt,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    modifier = Modifier
                        .weight(1f)
                        .minimumInteractiveComponentSize()
                        .testTag("export_txt_button")
                ) {
                    Icon(Icons.Filled.Description, null, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(strings.exportTxt, maxLines = 1, softWrap = false)
                }
                OutlinedButton(
                    onClick = onExportJson,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    modifier = Modifier
                        .weight(1f)
                        .minimumInteractiveComponentSize()
                        .testTag("export_json_button")
                ) {
                    Icon(Icons.Filled.SaveAlt, null, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(strings.exportJson, maxLines = 1, softWrap = false)
                }
            }
        }

        if (rawMode) {
            val rawReport = remember(report, language) {
                ReportFormatter.formatPlainText(report, language)
            }
            Surface(
                shape = MaterialTheme.shapes.medium,
                color = LocalSemanticColors.current.codeSurface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                modifier = Modifier.fillMaxWidth()
            ) {
                SelectionContainer {
                    Text(
                        text = rawReport,
                        fontFamily = JetBrainsMonoFontFamily,
                        fontSize = 11.5.sp,
                        lineHeight = 16.5.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState())
                            .padding(14.dp)
                            .testTag("raw_report_text")
                    )
                }
            }
        } else {
            VerdictSummaryCard(report = report, strings = strings, onCopy = onCopyText)

            if (report.schemeDetails.isNotEmpty()) {
                SchemeMatrixCard(report = report, strings = strings)
            }

            if (report.errors.isNotEmpty() || report.warnings.isNotEmpty()) {
                DiagnosticsCard(report = report, strings = strings)
            }

            report.certificates.forEach { cert ->
                CertificateCard(
                    cert = cert,
                    language = language,
                    strings = strings,
                    onCopy = onCopyText
                )
            }

            AdvancedSchemePanels(
                report = report,
                language = language,
                strings = strings,
                onCopy = onCopyText
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun VerdictSummaryCard(
    report: ApkVerificationReport,
    strings: UiStrings,
    onCopy: (String) -> Unit
) {
    val semantic = LocalSemanticColors.current
    val (statusLabel, statusColor, statusBg, statusIcon) = when {
        !report.isVerified -> Quad(
            strings.statusFailed,
            MaterialTheme.colorScheme.error,
            MaterialTheme.colorScheme.errorContainer,
            Icons.Filled.Error
        )
        report.warnings.isNotEmpty() -> Quad(
            strings.statusWithWarnings,
            semantic.warning,
            semantic.warningContainer,
            Icons.Filled.Warning
        )
        else -> Quad(
            strings.statusVerified,
            semantic.verified,
            semantic.verifiedContainer,
            Icons.Filled.CheckCircle
        )
    }

    Surface(
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Surface(shape = MaterialTheme.shapes.small, color = statusBg) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(statusIcon, contentDescription = null, tint = statusColor, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = statusLabel,
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = statusColor
                        )
                    }
                }
                Text(
                    text = formatByteSize(report.fileSizeBytes),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            val versionSuffix = buildString {
                if (!report.versionName.isNullOrBlank()) append(" v${report.versionName.removePrefix("v")}")
                if (report.versionCode != null) append(" (${report.versionCode})")
            }
            Text(
                text = "${report.appLabel}$versionSuffix",
                style = MaterialTheme.typography.headlineSmall
            )
            if (!report.packageName.isNullOrBlank()) {
                Text(
                    text = report.packageName,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            // Detected schemes chips
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (report.detectedSchemes.isEmpty()) {
                    AssistChip(onClick = {}, label = { Text(strings.reportNone) })
                } else {
                    report.detectedSchemes.forEach { scheme ->
                        val verified = report.verifiedSchemes.contains(scheme)
                        Surface(
                            shape = MaterialTheme.shapes.extraSmall,
                            color = if (verified) semantic.verifiedContainer else MaterialTheme.colorScheme.errorContainer,
                            border = BorderStroke(
                                1.dp,
                                if (verified) semantic.verified.copy(alpha = 0.4f) else MaterialTheme.colorScheme.error.copy(alpha = 0.4f)
                            )
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = if (verified) Icons.Filled.VerifiedUser else Icons.Filled.Warning,
                                    contentDescription = null,
                                    tint = if (verified) semantic.verified else MaterialTheme.colorScheme.error,
                                    modifier = Modifier.size(13.dp)
                                )
                                Spacer(Modifier.width(4.dp))
                                Text(
                                    text = scheme.label,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (verified) semantic.verified else MaterialTheme.colorScheme.error
                                )
                            }
                        }
                    }
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            MonoKeyValueRow(strings.reportPath, report.filePath, onCopy)
            if (report.minSdk != null || report.targetSdk != null) {
                MonoKeyValueRow(
                    strings.labelSdk,
                    "min ${report.minSdk ?: "-"} / target ${report.targetSdk ?: "-"}",
                    onCopy
                )
            }
            report.isDebuggable?.let { dbg ->
                MonoKeyValueRow(strings.labelDebuggable, dbg.toString(), onCopy)
            }
            MonoKeyValueRow(
                strings.labelZipInfo,
                "${report.zipEntryCount} entries • 4-byte aligned: ${report.isZipAligned4}",
                onCopy
            )
            MonoKeyValueRow(strings.labelApkSha256, report.apkSha256, onCopy)
            MonoKeyValueRow(strings.labelApkSha1, report.apkSha1, onCopy)
            MonoKeyValueRow(strings.labelApkMd5, report.apkMd5, onCopy)
            MonoKeyValueRow(strings.labelApkCrc32, report.apkCrc32Hex, onCopy)
        }
    }
}

@Composable
private fun SchemeMatrixCard(report: ApkVerificationReport, strings: UiStrings) {
    val semantic = LocalSemanticColors.current
    Surface(
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(strings.sectionSchemeMatrix, style = MaterialTheme.typography.titleSmall)
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            report.schemeDetails.forEach { d ->
                val color = if (d.isVerified) semantic.verified else MaterialTheme.colorScheme.error
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = d.scheme.label,
                        style = MaterialTheme.typography.labelLarge,
                        color = color
                    )
                    val info = buildList {
                        add("${d.signerCount} signer(s)")
                        d.sdkRange?.let { add(it) }
                        if (d.digestAlgorithms.isNotEmpty()) add(d.digestAlgorithms.joinToString("/"))
                        if (d.signatureAlgorithms.isNotEmpty()) add(d.signatureAlgorithms.joinToString("/"))
                        d.notes?.let { add(it) }
                    }.joinToString(" • ")
                    Text(
                        text = info,
                        fontFamily = JetBrainsMonoFontFamily,
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 12.dp),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

@Composable
private fun DiagnosticsCard(report: ApkVerificationReport, strings: UiStrings) {
    val semantic = LocalSemanticColors.current
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(strings.sectionDiagnostics, style = MaterialTheme.typography.titleSmall)
            report.errors.forEach { err ->
                Text(
                    text = "• $err",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
            report.warnings.forEach { warn ->
                Text(
                    text = "• $warn",
                    style = MaterialTheme.typography.bodySmall,
                    color = semantic.warning
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CertificateCard(
    cert: CertificateDetails,
    language: AppLanguage,
    strings: UiStrings,
    onCopy: (String) -> Unit
) {
    val semantic = LocalSemanticColors.current
    var showRawBlobs by rememberSaveable(cert.sha256, cert.index) { mutableStateOf(false) }

    Surface(
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Security,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = strings.reportCertificateTitle(cert.index),
                        style = MaterialTheme.typography.titleMedium
                    )
                }

                val (valLabel, valColor) = when (cert.validityStatus) {
                    ValidityStatus.VALID -> "${strings.reportValidityOk} (${cert.daysRemaining}d)" to semantic.verified
                    ValidityStatus.EXPIRED -> strings.reportValidityExpired to MaterialTheme.colorScheme.error
                    ValidityStatus.NOT_YET_VALID -> strings.reportValidityNotYet to semantic.warning
                }
                Text(
                    text = valLabel,
                    style = MaterialTheme.typography.labelMedium,
                    color = valColor
                )
            }

            if (cert.schemeTags.isNotEmpty() || cert.knownSignerHint != null) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    cert.schemeTags.forEach { tag ->
                        Surface(
                            shape = MaterialTheme.shapes.extraSmall,
                            color = MaterialTheme.colorScheme.primaryContainer
                        ) {
                            Text(
                                text = tag,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                    cert.knownSignerHint?.let { hint ->
                        Surface(
                            shape = MaterialTheme.shapes.extraSmall,
                            color = MaterialTheme.colorScheme.tertiaryContainer
                        ) {
                            Text(
                                text = hint,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            MonoKeyValueRow(strings.reportCertType, "${cert.type} (v${cert.version})", onCopy)
            MonoKeyValueRow(strings.reportSerial, "${cert.serialNumberDecimal} (${cert.serialNumberHex})", onCopy)
            MonoKeyValueRow(strings.reportOwner, cert.subjectDn, onCopy)
            MonoKeyValueRow(
                strings.reportIssuer,
                if (cert.isSelfSigned) strings.reportSelfSigned else cert.issuerDn,
                onCopy
            )
            MonoKeyValueRow(
                strings.reportValidity,
                strings.reportValidityRange(
                    ReportFormatter.formatDate(cert.notBeforeMs, language),
                    ReportFormatter.formatDate(cert.notAfterMs, language)
                ),
                onCopy
            )
            MonoKeyValueRow(
                strings.reportSigAlg,
                "${cert.sigAlgName} (${cert.publicKeyAlgorithm} ${cert.publicKeySizeBits} bits)",
                onCopy
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            MonoKeyValueRow(strings.reportHashCode, "${cert.hashCodeHex} (${cert.hashCodeInt})", onCopy)
            MonoKeyValueRow(strings.reportCrc32, "${cert.crc32Hex} (${cert.crc32Long})", onCopy)
            MonoKeyValueRow(strings.reportMd5, cert.md5, onCopy)
            MonoKeyValueRow(strings.reportSha1, cert.sha1, onCopy)
            MonoKeyValueRow(strings.labelSha1Colon, cert.sha1Colon, onCopy)
            MonoKeyValueRow(strings.reportSha224, cert.sha224, onCopy)
            MonoKeyValueRow(strings.reportSha256, cert.sha256, onCopy)
            MonoKeyValueRow(strings.labelSha256Colon, cert.sha256Colon, onCopy)
            MonoKeyValueRow(strings.reportSha384, cert.sha384, onCopy)
            MonoKeyValueRow(strings.reportSha512, cert.sha512, onCopy)

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { showRawBlobs = !showRawBlobs }
                    .padding(vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = "${strings.reportPublicKey} • Base64 • Bits • X.509",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                Icon(
                    imageVector = if (showRawBlobs) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = strings.tapToExpand,
                    tint = MaterialTheme.colorScheme.primary
                )
            }

            AnimatedVisibility(visible = showRawBlobs) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    MonoKeyValueRow(strings.reportPublicKey, cert.publicKeySummary, onCopy)
                    MonoKeyValueRow(strings.labelSpkiSha256, cert.publicKeySpkiSha256, onCopy)
                    if (cert.keyUsage.isNotEmpty()) {
                        MonoKeyValueRow(strings.labelKeyUsage, cert.keyUsage.joinToString(", "), onCopy)
                    }
                    if (cert.extendedKeyUsage.isNotEmpty()) {
                        MonoKeyValueRow(strings.labelExtendedKeyUsage, cert.extendedKeyUsage.joinToString(", "), onCopy)
                    }
                    cert.basicConstraints?.let {
                        MonoKeyValueRow(strings.labelBasicConstraints, it, onCopy)
                    }
                    cert.subjectKeyIdentifier?.let {
                        MonoKeyValueRow(strings.labelSki, it, onCopy)
                    }
                    cert.authorityKeyIdentifier?.let {
                        MonoKeyValueRow(strings.labelAki, it, onCopy)
                    }
                    MonoKeyValueRow(strings.reportCertBase64, cert.certBase64, onCopy)
                    MonoKeyValueRow(strings.reportSigBits, cert.signatureBitsHex, onCopy)
                    MonoKeyValueRow(strings.reportSigBase64, cert.signatureBase64, onCopy)
                }
            }
        }
    }
}

@Composable
private fun AdvancedSchemePanels(
    report: ApkVerificationReport,
    language: AppLanguage,
    strings: UiStrings,
    onCopy: (String) -> Unit
) {
    var expanded by rememberSaveable(report.id) { mutableStateOf(false) }

    Surface(
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(strings.sectionAdvancedCrypto, style = MaterialTheme.typography.titleSmall)
                Icon(
                    imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = strings.tapToExpand
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (report.v3Lineage.isNotEmpty()) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        Text(strings.sectionLineageV3, style = MaterialTheme.typography.labelLarge)
                        report.v3Lineage.forEach { node ->
                            MonoKeyValueRow("#${node.index} ${node.sigAlg}", node.subjectDn, onCopy)
                            MonoKeyValueRow("SHA-256", node.certSha256, onCopy)
                            if (node.capabilities.isNotEmpty()) {
                                MonoKeyValueRow("Capabilities", node.capabilities.joinToString(", "), onCopy)
                            }
                        }
                    }

                    report.sourceStamp?.let { stamp ->
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        Text(strings.sectionSourceStamp, style = MaterialTheme.typography.labelLarge)
                        MonoKeyValueRow("Verified", stamp.isVerified.toString(), onCopy)
                        stamp.stampDigestSha256?.let { MonoKeyValueRow("Stamp SHA-256", it, onCopy) }
                        stamp.certificate?.let { sc ->
                            MonoKeyValueRow(strings.reportOwner, sc.subjectDn, onCopy)
                            MonoKeyValueRow(
                                strings.reportValidity,
                                strings.reportValidityRange(
                                    ReportFormatter.formatDate(sc.notBeforeMs, language),
                                    ReportFormatter.formatDate(sc.notAfterMs, language)
                                ),
                                onCopy
                            )
                        }
                    }

                    report.v1JarDetails?.let { v1 ->
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        Text(strings.sectionV1Jar, style = MaterialTheme.typography.labelLarge)
                        MonoKeyValueRow("Verified", v1.isVerified.toString(), onCopy)
                        MonoKeyValueRow("Signers", v1.signerFiles.joinToString(", ").ifEmpty { "-" }, onCopy)
                        MonoKeyValueRow("SF Files", v1.sfFiles.joinToString(", ").ifEmpty { "-" }, onCopy)
                        MonoKeyValueRow(
                            "Digests",
                            v1.digestAlgorithms.joinToString(", ").ifEmpty { "-" },
                            onCopy
                        )
                        MonoKeyValueRow("Entries", "${v1.signedEntryCount}/${v1.totalJarEntryCount}", onCopy)
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Text(strings.sectionSigningBlock, style = MaterialTheme.typography.labelLarge)
                    if (report.signingBlockInfo.present) {
                        MonoKeyValueRow(
                            "Block",
                            "Offset 0x${report.signingBlockInfo.blockOffset.toString(16)} • ${report.signingBlockInfo.blockSizeBytes} B",
                            onCopy
                        )
                        report.signingBlockInfo.pairs.forEach { pair ->
                            MonoKeyValueRow(pair.idHex, "${pair.name} (${pair.sizeBytes} B)", onCopy)
                        }
                    } else {
                        MonoKeyValueRow("Block", "Not present", onCopy)
                    }
                    if (report.signingBlockInfo.contentDigestAlgorithms.isNotEmpty()) {
                        MonoKeyValueRow(
                            "Content Digests",
                            report.signingBlockInfo.contentDigestAlgorithms.joinToString(", "),
                            onCopy
                        )
                    }
                    if (report.signingBlockInfo.v4IdsigFound) {
                        MonoKeyValueRow(
                            "V4 .idsig",
                            "${report.signingBlockInfo.v4IdsigPath} (verified=${report.signingBlockInfo.v4Verified})",
                            onCopy
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MonoKeyValueRow(
    label: String,
    value: String,
    onCopy: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(2.dp))
            SelectionContainer {
                Text(
                    text = value,
                    fontFamily = JetBrainsMonoFontFamily,
                    fontSize = 11.5.sp,
                    lineHeight = 16.sp,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
        IconButton(
            onClick = { onCopy(value) },
            modifier = Modifier.size(36.dp)
        ) {
            Icon(
                imageVector = Icons.Filled.ContentCopy,
                contentDescription = label,
                modifier = Modifier.size(15.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private data class Quad<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
