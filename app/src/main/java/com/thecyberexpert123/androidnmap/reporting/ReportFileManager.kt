package com.thecyberexpert123.androidnmap.reporting

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import com.thecyberexpert123.nmaptool.contract.ReportExportFormat
import java.io.File
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

private const val REPORT_CACHE_DIR = "reports"
private const val FILE_PROVIDER_AUTHORITY_SUFFIX = ".fileprovider"

object ReportFileManager {
    fun buildSuggestedFileName(
        format: ReportExportFormat,
        filterLabel: String,
        maxRuns: Int,
        generatedAtEpochMillis: Long = System.currentTimeMillis(),
    ): String {
        val timestamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
            .withZone(ZoneOffset.UTC)
            .format(Instant.ofEpochMilli(generatedAtEpochMillis))
        val normalizedFilter = filterLabel.lowercase()
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .ifBlank { "all-tools" }
        val extension = when (format) {
            ReportExportFormat.MARKDOWN -> "md"
            ReportExportFormat.CSV -> "csv"
        }
        return "android-nmap-tool-$normalizedFilter-latest-$maxRuns-$timestamp.$extension"
    }

    fun mimeType(format: ReportExportFormat): String = when (format) {
        ReportExportFormat.MARKDOWN -> "text/markdown"
        ReportExportFormat.CSV -> "text/csv"
    }

    fun writeReportToUri(
        context: Context,
        destination: Uri,
        content: String,
    ) {
        requireNotNull(context.contentResolver.openOutputStream(destination, "w")) {
            "Failed to open the selected export destination."
        }.bufferedWriter(StandardCharsets.UTF_8).use { writer ->
            writer.write(content)
        }
    }

    fun createShareIntent(
        context: Context,
        format: ReportExportFormat,
        fileName: String,
        content: String,
    ): Intent {
        val reportDir = File(context.cacheDir, REPORT_CACHE_DIR).apply { mkdirs() }
        val reportFile = File(reportDir, fileName)
        reportFile.writeText(content, StandardCharsets.UTF_8)
        val contentUri = FileProvider.getUriForFile(
            context,
            context.packageName + FILE_PROVIDER_AUTHORITY_SUFFIX,
            reportFile,
        )
        return Intent(Intent.ACTION_SEND).apply {
            type = mimeType(format)
            putExtra(Intent.EXTRA_STREAM, contentUri)
            putExtra(Intent.EXTRA_SUBJECT, fileName)
            putExtra(Intent.EXTRA_TEXT, "Android Nmap Tool execution report")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            clipData = android.content.ClipData.newRawUri(fileName, contentUri)
        }
    }
}
