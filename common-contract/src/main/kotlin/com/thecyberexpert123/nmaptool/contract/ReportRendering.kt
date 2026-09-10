package com.thecyberexpert123.nmaptool.contract

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlin.math.roundToLong

enum class ReportExportFormat {
    MARKDOWN,
    CSV,
}

data class ExecutionReportItem(
    val profileName: String,
    val tool: ToolType,
    val route: ExecutionRoute,
    val status: RunStatus,
    val trigger: RunTrigger,
    val commandPreview: String,
    val message: String,
    val startedAtEpochMillis: Long,
    val finishedAtEpochMillis: Long,
    val parseSource: ResultParseSource,
    val overview: String,
    val observedHosts: List<String> = emptyList(),
    val portFindings: List<PortFinding> = emptyList(),
    val hostDetails: List<HostDetail> = emptyList(),
    val scriptFindings: List<ScriptFinding> = emptyList(),
    val newOpenPorts: List<PortFinding> = emptyList(),
    val closedPorts: List<PortFinding> = emptyList(),
    val warnings: List<String> = emptyList(),
    val requestId: String? = null,
    val executorLabel: String? = null,
)

object ExecutionReportRenderer {
    fun render(
        format: ReportExportFormat,
        title: String,
        items: List<ExecutionReportItem>,
        generatedAtEpochMillis: Long = System.currentTimeMillis(),
    ): String = when (format) {
        ReportExportFormat.MARKDOWN -> renderMarkdown(title, items, generatedAtEpochMillis)
        ReportExportFormat.CSV -> renderCsv(items)
    }

    fun renderMarkdown(
        title: String,
        items: List<ExecutionReportItem>,
        generatedAtEpochMillis: Long = System.currentTimeMillis(),
    ): String {
        val succeeded = items.count { it.status == RunStatus.SUCCEEDED }
        val failed = items.count { it.status == RunStatus.FAILED }
        val blocked = items.count { it.status == RunStatus.BLOCKED }
        val structured = items.count { it.parseSource == ResultParseSource.STRUCTURED_NMAP_XML }
        val heuristic = items.count { it.parseSource == ResultParseSource.HEURISTIC_TEXT }
        val warningsCount = items.sumOf { it.warnings.size }

        return buildString {
            appendLine("# $title")
            appendLine()
            appendLine("Generated: ${formatTimestamp(generatedAtEpochMillis)}")
            appendLine("Runs included: ${items.size}")
            appendLine()
            appendLine("## Summary")
            appendLine("- Succeeded: $succeeded")
            appendLine("- Failed: $failed")
            appendLine("- Blocked: $blocked")
            appendLine("- Structured XML parsed runs: $structured")
            appendLine("- Heuristic parsed runs: $heuristic")
            appendLine("- Reported warnings: $warningsCount")

            if (items.isEmpty()) {
                appendLine()
                appendLine("No runs were available for export.")
                return@buildString
            }

            items.forEachIndexed { index, item ->
                appendLine()
                appendLine("## Run ${index + 1} — ${item.profileName}")
                appendLine("- Tool: ${item.tool.name}")
                appendLine("- Status: ${item.status.name}")
                appendLine("- Route: ${item.route.name}")
                appendLine("- Trigger: ${item.trigger.name}")
                appendLine("- Started: ${formatTimestamp(item.startedAtEpochMillis)}")
                appendLine("- Duration: ${formatDuration(item.finishedAtEpochMillis - item.startedAtEpochMillis)}")
                appendLine("- Parse source: ${formatParseSource(item.parseSource)}")
                item.executorLabel?.takeIf(String::isNotBlank)?.let { appendLine("- Executor: $it") }
                item.requestId?.takeIf(String::isNotBlank)?.let { appendLine("- Request ID: $it") }
                appendLine("- Overview: ${item.overview}")
                appendLine("- Observed hosts: ${item.observedHosts.size}")
                appendLine("- Parsed endpoints: ${item.portFindings.size}")
                appendLine("- Host detail blocks: ${item.hostDetails.size}")
                appendLine("- Script results: ${item.scriptFindings.size}")
                appendLine("- Command: `${item.commandPreview}`")
                if (item.message.isNotBlank()) {
                    appendLine("- Message: ${item.message}")
                }
                if (item.warnings.isNotEmpty()) {
                    appendLine("- Warnings:")
                    item.warnings.forEach { warning -> appendLine("  - $warning") }
                }
                if (item.observedHosts.isNotEmpty()) {
                    appendLine("- Hosts:")
                    item.observedHosts.forEach { host -> appendLine("  - $host") }
                }
                if (item.hostDetails.isNotEmpty()) {
                    appendLine("- Host details:")
                    item.hostDetails.forEach { hostDetail ->
                        appendLine("  - ${formatHostDetail(hostDetail)}")
                    }
                }
                if (item.scriptFindings.isNotEmpty()) {
                    appendLine("- Script results:")
                    item.scriptFindings.forEach { scriptFinding ->
                        appendLine("  - ${formatScriptFinding(scriptFinding)}")
                    }
                }
                if (item.newOpenPorts.isNotEmpty()) {
                    appendLine("- New open ports since previous run:")
                    item.newOpenPorts.forEach { finding -> appendLine("  - ${formatFinding(finding)}") }
                }
                if (item.closedPorts.isNotEmpty()) {
                    appendLine("- Previously open ports no longer present:")
                    item.closedPorts.forEach { finding -> appendLine("  - ${formatFinding(finding)}") }
                }
                if (item.portFindings.isNotEmpty()) {
                    appendLine("- Parsed findings:")
                    item.portFindings.forEach { finding -> appendLine("  - ${formatFinding(finding)}") }
                }
            }
        }.trimEnd()
    }

    fun renderCsv(items: List<ExecutionReportItem>): String {
        val header = listOf(
            "profile_name",
            "tool",
            "status",
            "route",
            "trigger",
            "started_at",
            "duration_seconds",
            "parse_source",
            "executor_label",
            "request_id",
            "overview",
            "observed_hosts",
            "parsed_endpoint_count",
            "host_details",
            "script_findings",
            "new_open_ports",
            "closed_ports",
            "warnings",
            "command_preview",
            "message",
        )

        val rows = items.map { item ->
            listOf(
                item.profileName,
                item.tool.name,
                item.status.name,
                item.route.name,
                item.trigger.name,
                formatTimestamp(item.startedAtEpochMillis),
                formatDurationSeconds(item.finishedAtEpochMillis - item.startedAtEpochMillis),
                formatParseSource(item.parseSource),
                item.executorLabel.orEmpty(),
                item.requestId.orEmpty(),
                item.overview,
                item.observedHosts.joinToString(separator = "; "),
                item.portFindings.size.toString(),
                item.hostDetails.joinToString(separator = "; ", transform = ::formatHostDetail),
                item.scriptFindings.joinToString(separator = "; ", transform = ::formatScriptFinding),
                item.newOpenPorts.joinToString(separator = "; ", transform = ::formatFinding),
                item.closedPorts.joinToString(separator = "; ", transform = ::formatFinding),
                item.warnings.joinToString(separator = "; "),
                item.commandPreview,
                item.message,
            )
        }

        return buildString {
            appendLine(header.joinToString(",") { escapeCsv(it) })
            rows.forEach { row -> appendLine(row.joinToString(",") { escapeCsv(it) }) }
        }.trimEnd()
    }

    private fun formatTimestamp(epochMillis: Long): String =
        DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(
            Instant.ofEpochMilli(epochMillis).atOffset(ZoneOffset.UTC),
        )

    private fun formatDuration(durationMillis: Long): String {
        val safeMillis = durationMillis.coerceAtLeast(0L)
        val totalSeconds = safeMillis / 1_000
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return if (minutes > 0) "$minutes m $seconds s" else "$seconds s"
    }

    private fun formatDurationSeconds(durationMillis: Long): String =
        (durationMillis.coerceAtLeast(0L).toDouble() / 1_000.0).let { seconds ->
            ((seconds * 100.0).roundToLong() / 100.0).toString()
        }

    private fun formatParseSource(parseSource: ResultParseSource): String = when (parseSource) {
        ResultParseSource.STRUCTURED_NMAP_XML -> "structured_nmap_xml"
        ResultParseSource.HEURISTIC_TEXT -> "heuristic_text"
        ResultParseSource.NONE -> "none"
    }

    private fun formatFinding(finding: PortFinding): String = buildString {
        finding.host?.takeIf(String::isNotBlank)?.let {
            append(it)
            append(' ')
        }
        append(finding.endpointLabel)
        append(' ')
        append(finding.state)
        append(' ')
        append(finding.service)
        if (finding.details.isNotBlank()) {
            append(" — ")
            append(finding.details)
        }
    }

    private fun formatHostDetail(hostDetail: HostDetail): String = buildString {
        append(hostDetail.host)
        if (hostDetail.status.isNotBlank()) {
            append(" [")
            append(hostDetail.status)
            append(']')
        }
        if (hostDetail.summaryLines.isNotEmpty()) {
            append(" — ")
            append(hostDetail.summaryLines.joinToString(separator = " | "))
        }
    }

    private fun formatScriptFinding(scriptFinding: ScriptFinding): String = buildString {
        append(scriptFinding.locationLabel)
        append(" :: ")
        append(scriptFinding.scriptId)
        append(" — ")
        append(scriptFinding.output)
    }

    private fun escapeCsv(value: String): String {
        val escaped = value.replace("\"", "\"\"")
        return if (escaped.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
            "\"$escaped\""
        } else {
            escaped
        }
    }
}
