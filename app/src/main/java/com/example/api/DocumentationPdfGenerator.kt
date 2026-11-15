package com.example.api

import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import com.example.model.AppLanguage
import java.io.OutputStream

object DocumentationPdfGenerator {

    private const val PAGE_WIDTH = 595 // A4 pt
    private const val PAGE_HEIGHT = 842
    private const val MARGIN_X = 42f
    private const val CONTENT_WIDTH = PAGE_WIDTH - (MARGIN_X * 2)
    private const val TOP_Y = 48f
    private const val BOTTOM_LIMIT = PAGE_HEIGHT - 46f

    private sealed interface DocBlock {
        data class Title(val text: String) : DocBlock
        data class Subtitle(val text: String) : DocBlock
        data class Heading(val text: String) : DocBlock
        data class Paragraph(val text: String) : DocBlock
        data class Bullet(val label: String, val desc: String) : DocBlock
        data class Code(val lines: List<String>) : DocBlock
        data object Spacer : DocBlock
    }

    fun generate(lang: AppLanguage, out: OutputStream) {
        val doc = PdfDocument()
        val blocks = buildBlocks(lang)

        val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(15, 23, 42)
            textSize = 20f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
        }
        val subtitlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(29, 78, 216)
            textSize = 11f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
        }
        val headingPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(15, 23, 42)
            textSize = 13.5f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
        }
        val bodyPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(51, 65, 85)
            textSize = 10f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
        }
        val boldBodyPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(15, 23, 42)
            textSize = 10f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
        }
        val codePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(15, 23, 42)
            textSize = 8.6f
            typeface = Typeface.MONOSPACE
        }
        val codeBgPaint = Paint().apply {
            color = Color.rgb(241, 245, 249)
            style = Paint.Style.FILL
        }
        val codeBorderPaint = Paint().apply {
            color = Color.rgb(203, 213, 225)
            style = Paint.Style.STROKE
            strokeWidth = 1f
        }
        val footerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(100, 116, 139)
            textSize = 8.5f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
        }

        var pageNum = 1
        var page = doc.startPage(PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, pageNum).create())
        var canvas = page.canvas
        var y = TOP_Y

        fun nextPage() {
            canvas.drawText("SignerLAB API v${SignerApiContract.API_VERSION}  —  Page $pageNum", MARGIN_X, PAGE_HEIGHT - 22f, footerPaint)
            doc.finishPage(page)
            pageNum++
            page = doc.startPage(PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, pageNum).create())
            canvas = page.canvas
            y = TOP_Y
        }

        fun ensureSpace(needed: Float) {
            if (y + needed > BOTTOM_LIMIT) {
                nextPage()
            }
        }

        blocks.forEach { block ->
            when (block) {
                is DocBlock.Title -> {
                    ensureSpace(28f)
                    canvas.drawText(block.text, MARGIN_X, y, titlePaint)
                    y += 24f
                }

                is DocBlock.Subtitle -> {
                    ensureSpace(18f)
                    canvas.drawText(block.text, MARGIN_X, y, subtitlePaint)
                    y += 18f
                }

                is DocBlock.Heading -> {
                    ensureSpace(26f)
                    y += 6f
                    canvas.drawText(block.text, MARGIN_X, y, headingPaint)
                    y += 6f
                    canvas.drawLine(MARGIN_X, y, MARGIN_X + CONTENT_WIDTH, y, codeBorderPaint)
                    y += 13f
                }

                is DocBlock.Paragraph -> {
                    val lines = wrapText(block.text, bodyPaint, CONTENT_WIDTH)
                    ensureSpace(lines.size * 14f + 4f)
                    lines.forEach { line ->
                        canvas.drawText(line, MARGIN_X, y, bodyPaint)
                        y += 14f
                    }
                    y += 3f
                }

                is DocBlock.Bullet -> {
                    val prefix = "• ${block.label}: "
                    val prefixWidth = boldBodyPaint.measureText(prefix)
                    val remaining = (CONTENT_WIDTH - prefixWidth).coerceAtLeast(140f)
                    val descLines = wrapText(block.desc, bodyPaint, remaining)
                    ensureSpace(descLines.size * 14f + 4f)
                    canvas.drawText(prefix, MARGIN_X, y, boldBodyPaint)
                    if (descLines.isNotEmpty()) {
                        canvas.drawText(descLines.first(), MARGIN_X + prefixWidth, y, bodyPaint)
                        y += 14f
                        descLines.drop(1).forEach { extra ->
                            canvas.drawText(extra, MARGIN_X + 12f, y, bodyPaint)
                            y += 14f
                        }
                    } else {
                        y += 14f
                    }
                }

                is DocBlock.Code -> {
                    val boxHeight = block.lines.size * 12.5f + 14f
                    ensureSpace(boxHeight + 8f)
                    val top = y - 8f
                    val bottom = top + boxHeight
                    canvas.drawRect(MARGIN_X, top, MARGIN_X + CONTENT_WIDTH, bottom, codeBgPaint)
                    canvas.drawRect(MARGIN_X, top, MARGIN_X + CONTENT_WIDTH, bottom, codeBorderPaint)
                    var cy = top + 15f
                    block.lines.forEach { line ->
                        canvas.drawText(line, MARGIN_X + 10f, cy, codePaint)
                        cy += 12.5f
                    }
                    y = bottom + 10f
                }

                DocBlock.Spacer -> {
                    y += 8f
                }
            }
        }

        canvas.drawText("SignerLAB API v${SignerApiContract.API_VERSION}  —  Page $pageNum", MARGIN_X, PAGE_HEIGHT - 22f, footerPaint)
        doc.finishPage(page)

        doc.writeTo(out)
        doc.close()
    }

    private fun wrapText(text: String, paint: Paint, maxWidth: Float): List<String> {
        val words = text.split(" ")
        val lines = mutableListOf<String>()
        var current = StringBuilder()
        words.forEach { word ->
            val candidate = if (current.isEmpty()) word else "$current $word"
            if (paint.measureText(candidate) <= maxWidth) {
                current = StringBuilder(candidate)
            } else {
                if (current.isNotEmpty()) lines += current.toString()
                current = StringBuilder(word)
            }
        }
        if (current.isNotEmpty()) lines += current.toString()
        return lines
    }

    internal fun documentationPreviewText(lang: AppLanguage): String {
        return buildBlocks(lang).joinToString("\n") { block ->
            when (block) {
                is DocBlock.Title -> block.text
                is DocBlock.Subtitle -> block.text
                is DocBlock.Heading -> block.text
                is DocBlock.Paragraph -> block.text
                is DocBlock.Bullet -> "${block.label}: ${block.desc}"
                is DocBlock.Code -> block.lines.joinToString("\n")
                DocBlock.Spacer -> ""
            }
        }
    }

    private fun buildBlocks(lang: AppLanguage): List<DocBlock> {
        return if (lang == AppLanguage.FR) buildFrenchBlocks() else buildEnglishBlocks()
    }

    private fun buildFrenchBlocks(): List<DocBlock> = listOf(
        DocBlock.Title("SignerLAB — Documentation API Inter-Application"),
        DocBlock.Subtitle("Version ${SignerApiContract.API_VERSION}  |  Package: ${SignerApiContract.PACKAGE_ID}"),
        DocBlock.Paragraph(
            "Ce document décrit les interfaces officielles permettant à une application Android externe de commander SignerLAB pour analyser des APK (schémas V1, V2, V3, V3.1, V4 et SourceStamp) et récupérer le résultat cryptographique complet."
        ),
        DocBlock.Heading("1. Déclaration requise (Android 11+ / API 30+)"),
        DocBlock.Paragraph(
            "Dans le fichier AndroidManifest.xml de votre application cliente, déclarez SignerLAB dans le bloc <queries> :"
        ),
        DocBlock.Code(
            listOf(
                "<queries>",
                "    <package android:name=\"${SignerApiContract.PACKAGE_ID}\" />",
                "    <intent>",
                "        <action android:name=\"${SignerApiContract.ACTION_VERIFY_APK}\" />",
                "    </intent>",
                "</queries>"
            )
        ),
        DocBlock.Heading("2. Méthode A : Commande par Intent (ActivityResult)"),
        DocBlock.Paragraph(
            "Lancez SignerLAB avec l'action dédiée ou via Deep Link. Lorsque return_result=true (ou via startActivityForResult), SignerLAB retourne automatiquement le rapport dans RESULT_OK."
        ),
        DocBlock.Bullet("Action Intent", SignerApiContract.ACTION_VERIFY_APK),
        DocBlock.Bullet("Deep Link URI", "${SignerApiContract.DEEP_LINK_SCHEME}://${SignerApiContract.DEEP_LINK_HOST}?path=/chemin/app.apk&auto=true"),
        DocBlock.Bullet("Extra apk_path", "(String) Chemin complet d'un APK local ou root."),
        DocBlock.Bullet("Extra apk_paths", "(ArrayList<String>) Liste de plusieurs chemins APK."),
        DocBlock.Bullet("Extra data / EXTRA_STREAM", "(Uri) URI content:// partageable avec FLAG_GRANT_READ_URI_PERMISSION."),
        DocBlock.Bullet("Extra auto_verify", "(Boolean, défaut true) Lance l'analyse dès l'ouverture."),
        DocBlock.Bullet("Extra return_result", "(Boolean, défaut false) Retourne les résultats via setResult(RESULT_OK)."),
        DocBlock.Bullet("Extra silent_return", "(Boolean, défaut false) Ferme SignerLAB immédiatement après retour."),
        DocBlock.Bullet("Extra lang", "(String) \"fr\" ou \"en\" pour forcer la langue du rapport."),
        DocBlock.Code(
            listOf(
                "val intent = Intent(\"${SignerApiContract.ACTION_VERIFY_APK}\").apply {",
                "    setPackage(\"${SignerApiContract.PACKAGE_ID}\")",
                "    putExtra(\"apk_path\", \"/storage/emulated/0/Download/app.apk\")",
                "    putExtra(\"auto_verify\", true)",
                "    putExtra(\"return_result\", true)",
                "    putExtra(\"silent_return\", true)",
                "    putExtra(\"lang\", \"fr\")",
                "}",
                "launcher.launch(intent)"
            )
        ),
        DocBlock.Heading("3. Méthode B : Commande synchrone sans UI (ContentProvider)"),
        DocBlock.Paragraph(
            "Pour interroger SignerLAB en arrière-plan sans ouvrir d'écran, appelez ContentResolver.call() sur un thread secondaire (Dispatchers.IO) :"
        ),
        DocBlock.Bullet("Autorité URI", SignerApiContract.PROVIDER_URI),
        DocBlock.Bullet("Méthode ping", "Retourne status=\"ok\", api_version, has_storage_access, has_su_binary."),
        DocBlock.Bullet("Méthode verify_apk", "Paramètre arg = chemin APK ou Bundle extras (apk_path, apk_paths, uri, lang)."),
        DocBlock.Code(
            listOf(
                "val uri = Uri.parse(\"${SignerApiContract.PROVIDER_URI}\")",
                "val extras = Bundle().apply {",
                "    putString(\"apk_path\", \"/data/app/.../base.apk\")",
                "    putString(\"lang\", \"fr\")",
                "}",
                "val res = context.contentResolver.call(uri, \"verify_apk\", null, extras)",
                "val isValid = res?.getBoolean(\"is_verified\") == true",
                "val json = res?.getString(\"result_json\")"
            )
        ),
        DocBlock.Heading("4. Format des données retournées (Bundle / Result)"),
        DocBlock.Bullet("is_verified", "(Boolean) Verdict global de validité cryptographique."),
        DocBlock.Bullet("detected_schemes", "(ArrayList<String>) Ex: [\"V1\", \"V2\", \"V3\", \"SourceStamp\"]."),
        DocBlock.Bullet("verified_schemes", "(ArrayList<String>) Schémas validés individuellement."),
        DocBlock.Bullet("cert_sha256_list", "(ArrayList<String>) Empreintes SHA-256 hex des certificats."),
        DocBlock.Bullet("package_name", "(String) Identifiant de paquet de l'APK analysé."),
        DocBlock.Bullet("result_json", "(String) Rapport complet structuré JSON (schéma v1.0)."),
        DocBlock.Bullet("result_text", "(String) Rapport texte détaillé prêt à afficher."),
        DocBlock.Bullet("error_message", "(String) Message d'erreur éventuel en cas d'échec.")
    )

    private fun buildEnglishBlocks(): List<DocBlock> = listOf(
        DocBlock.Title("SignerLAB — Inter-App Command API Documentation"),
        DocBlock.Subtitle("Version ${SignerApiContract.API_VERSION}  |  Package: ${SignerApiContract.PACKAGE_ID}"),
        DocBlock.Paragraph(
            "This specification defines how external Android apps and automation tools can command SignerLAB to verify APK signatures (V1, V2, V3, V3.1, V4, and SourceStamp) and retrieve structured cryptographic results."
        ),
        DocBlock.Heading("1. Caller Manifest Declaration (Android 11+ / API 30+)"),
        DocBlock.Paragraph(
            "Add SignerLAB to the <queries> element in your caller app's AndroidManifest.xml:"
        ),
        DocBlock.Code(
            listOf(
                "<queries>",
                "    <package android:name=\"${SignerApiContract.PACKAGE_ID}\" />",
                "    <intent>",
                "        <action android:name=\"${SignerApiContract.ACTION_VERIFY_APK}\" />",
                "    </intent>",
                "</queries>"
            )
        ),
        DocBlock.Heading("2. Method A: Intent Command (ActivityResultLauncher)"),
        DocBlock.Paragraph(
            "Launch SignerLAB using the dedicated action or deep link. When return_result=true, SignerLAB returns full results via RESULT_OK."
        ),
        DocBlock.Bullet("Intent Action", SignerApiContract.ACTION_VERIFY_APK),
        DocBlock.Bullet("Deep Link URI", "${SignerApiContract.DEEP_LINK_SCHEME}://${SignerApiContract.DEEP_LINK_HOST}?path=/path/app.apk&auto=true"),
        DocBlock.Bullet("Extra apk_path", "(String) Full path to a local or root-protected APK."),
        DocBlock.Bullet("Extra apk_paths", "(ArrayList<String>) List of multiple APK paths."),
        DocBlock.Bullet("Extra data / EXTRA_STREAM", "(Uri) Content URI with FLAG_GRANT_READ_URI_PERMISSION."),
        DocBlock.Bullet("Extra auto_verify", "(Boolean, default true) Runs verification automatically."),
        DocBlock.Bullet("Extra return_result", "(Boolean, default false) Sends output Bundle back via setResult()."),
        DocBlock.Bullet("Extra silent_return", "(Boolean, default false) Closes UI right after returning result."),
        DocBlock.Bullet("Extra lang", "(String) \"fr\" or \"en\" report language override."),
        DocBlock.Code(
            listOf(
                "val intent = Intent(\"${SignerApiContract.ACTION_VERIFY_APK}\").apply {",
                "    setPackage(\"${SignerApiContract.PACKAGE_ID}\")",
                "    putExtra(\"apk_path\", \"/storage/emulated/0/Download/app.apk\")",
                "    putExtra(\"auto_verify\", true)",
                "    putExtra(\"return_result\", true)",
                "    putExtra(\"silent_return\", true)",
                "    putExtra(\"lang\", \"en\")",
                "}",
                "launcher.launch(intent)"
            )
        ),
        DocBlock.Heading("3. Method B: Headless Synchronous Call (ContentProvider)"),
        DocBlock.Paragraph(
            "To command SignerLAB in the background without opening UI, invoke ContentResolver.call() on a background thread (Dispatchers.IO):"
        ),
        DocBlock.Bullet("Provider URI", SignerApiContract.PROVIDER_URI),
        DocBlock.Bullet("Method ping", "Returns status=\"ok\", api_version, has_storage_access, has_su_binary."),
        DocBlock.Bullet("Method verify_apk", "Pass arg = APK path or Bundle extras (apk_path, apk_paths, uri, lang)."),
        DocBlock.Code(
            listOf(
                "val uri = Uri.parse(\"${SignerApiContract.PROVIDER_URI}\")",
                "val extras = Bundle().apply {",
                "    putString(\"apk_path\", \"/data/app/.../base.apk\")",
                "    putString(\"lang\", \"en\")",
                "}",
                "val res = context.contentResolver.call(uri, \"verify_apk\", null, extras)",
                "val isValid = res?.getBoolean(\"is_verified\") == true",
                "val json = res?.getString(\"result_json\")"
            )
        ),
        DocBlock.Heading("4. Returned Result Schema (Bundle Keys)"),
        DocBlock.Bullet("is_verified", "(Boolean) Overall cryptographic verification verdict."),
        DocBlock.Bullet("detected_schemes", "(ArrayList<String>) e.g. [\"V1\", \"V2\", \"V3\", \"SourceStamp\"]."),
        DocBlock.Bullet("verified_schemes", "(ArrayList<String>) Individually verified schemes."),
        DocBlock.Bullet("cert_sha256_list", "(ArrayList<String>) Signer certificate SHA-256 hex digests."),
        DocBlock.Bullet("package_name", "(String) Target APK package name."),
        DocBlock.Bullet("result_json", "(String) Full structured JSON report (API v1.0)."),
        DocBlock.Bullet("result_text", "(String) Full formatted plain-text report."),
        DocBlock.Bullet("error_message", "(String) Error description if verification failed.")
    )
}
