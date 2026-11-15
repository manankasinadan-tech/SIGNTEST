package com.example.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.api.SignerApiContract
import com.example.model.AppLanguage
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.LocalSemanticColors

@Composable
fun HelpDocumentationDialog(
    language: AppLanguage,
    strings: UiStrings,
    onDismiss: () -> Unit,
    onDownloadPdf: () -> Unit,
    onCopySnippet: (String) -> Unit
) {
    BackHandler(onBack = onDismiss)

    val kotlinSnippet = """
        // 1) Commande via Intent (avec retour résultat)
        val intent = Intent("${SignerApiContract.ACTION_VERIFY_APK}").apply {
            setPackage("${SignerApiContract.PACKAGE_ID}")
            putExtra("${SignerApiContract.EXTRA_APK_PATH}", "/storage/emulated/0/app.apk")
            putExtra("${SignerApiContract.EXTRA_AUTO_VERIFY}", true)
            putExtra("${SignerApiContract.EXTRA_RETURN_RESULT}", true)
            putExtra("${SignerApiContract.EXTRA_SILENT_RETURN}", true)
        }
        launcher.launch(intent)

        // 2) Commande synchrone sans UI (ContentProvider)
        val uri = Uri.parse("${SignerApiContract.PROVIDER_URI}")
        val args = Bundle().apply {
            putString("${SignerApiContract.EXTRA_APK_PATH}", "/data/app/.../base.apk")
            putString("${SignerApiContract.EXTRA_LANG}", "${language.code}")
        }
        val res = context.contentResolver.call(uri, "${SignerApiContract.METHOD_VERIFY_APK}", null, args)
        val isVerified = res?.getBoolean("${SignerApiContract.RESULT_IS_VERIFIED}") == true
        val json = res?.getString("${SignerApiContract.RESULT_JSON}")
    """.trimIndent()

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.95f)
                .fillMaxHeight(0.88f)
                .testTag("help_documentation_dialog"),
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 6.dp,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                // Header
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 20.dp, end = 8.dp, top = 14.dp, bottom = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = strings.helpTitle,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Filled.Close, contentDescription = strings.close)
                    }
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState())
                        .padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = strings.helpIntro,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    DocCard(
                        title = if (language == AppLanguage.FR) "1. Points d'entrée disponibles" else "1. Available Entry Points",
                        lines = listOf(
                            "• Intent Action : ${SignerApiContract.ACTION_VERIFY_APK}",
                            "• Deep Link : ${SignerApiContract.DEEP_LINK_SCHEME}://${SignerApiContract.DEEP_LINK_HOST}?path=...",
                            "• ContentProvider : ${SignerApiContract.PROVIDER_URI}",
                            "• Méthodes RPC : ${SignerApiContract.METHOD_PING}, ${SignerApiContract.METHOD_VERIFY_APK}"
                        )
                    )

                    DocCard(
                        title = if (language == AppLanguage.FR) "2. Paramètres d'entrée (Extras / Bundle)" else "2. Input Parameters (Extras / Bundle)",
                        lines = listOf(
                            "• ${SignerApiContract.EXTRA_APK_PATH} (String) : chemin APK",
                            "• ${SignerApiContract.EXTRA_APK_PATHS} (ArrayList<String>) : lot multi-APK",
                            "• ${SignerApiContract.EXTRA_URI} / data (Uri) : URI content://",
                            "• ${SignerApiContract.EXTRA_AUTO_VERIFY} (Boolean) : analyse auto",
                            "• ${SignerApiContract.EXTRA_RETURN_RESULT} (Boolean) : retour via setResult()",
                            "• ${SignerApiContract.EXTRA_SILENT_RETURN} (Boolean) : fermeture après retour",
                            "• ${SignerApiContract.EXTRA_LANG} (\"fr\" | \"en\") : langue du rapport"
                        )
                    )

                    DocCard(
                        title = if (language == AppLanguage.FR) "3. Données retournées" else "3. Returned Output Keys",
                        lines = listOf(
                            "• ${SignerApiContract.RESULT_IS_VERIFIED} (Boolean)",
                            "• ${SignerApiContract.RESULT_DETECTED_SCHEMES} (ArrayList<String>)",
                            "• ${SignerApiContract.RESULT_VERIFIED_SCHEMES} (ArrayList<String>)",
                            "• ${SignerApiContract.RESULT_CERT_SHA256_LIST} (ArrayList<String>)",
                            "• ${SignerApiContract.RESULT_PACKAGE_NAME} (String)",
                            "• ${SignerApiContract.RESULT_JSON} (String — JSON v1.0)",
                            "• ${SignerApiContract.RESULT_TEXT} (String — rapport brut)"
                        )
                    )

                    Text(
                        text = if (language == AppLanguage.FR) "4. Exemple d'intégration Kotlin" else "4. Kotlin Integration Snippet",
                        style = MaterialTheme.typography.titleSmall
                    )

                    Surface(
                        shape = MaterialTheme.shapes.medium,
                        color = LocalSemanticColors.current.codeSurface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = kotlinSnippet,
                            fontFamily = JetBrainsMonoFontFamily,
                            fontSize = 11.sp,
                            lineHeight = 15.5.sp,
                            modifier = Modifier
                                .horizontalScroll(rememberScrollState())
                                .padding(12.dp)
                        )
                    }

                    OutlinedButton(
                        onClick = { onCopySnippet(kotlinSnippet) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Filled.ContentCopy, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(strings.helpCopySnippet)
                    }
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                // Footer with PDF Download CTA
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = onDownloadPdf,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                            .testTag("download_api_pdf_button")
                    ) {
                        Icon(Icons.Filled.PictureAsPdf, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(strings.helpDownloadPdf, maxLines = 1)
                    }
                }
            }
        }
    }
}

@Composable
private fun DocCard(title: String, lines: List<String>) {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(2.dp))
            lines.forEach { line ->
                Text(
                    text = line,
                    fontFamily = JetBrainsMonoFontFamily,
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}
