package com.thecyberexpert123.androidnmap.reporting

import com.thecyberexpert123.androidnmap.data.ScanRunSummary
import com.thecyberexpert123.nmaptool.contract.ExecutionReportItem
import com.thecyberexpert123.nmaptool.contract.ExecutionReportRenderer
import com.thecyberexpert123.nmaptool.contract.ReportExportFormat
import com.thecyberexpert123.nmaptool.contract.RunStatus
import com.thecyberexpert123.nmaptool.contract.ToolType

fun buildExecutionReport(
    runs: List<ScanRunSummary>,
    format: ReportExportFormat,
    title: String,
    maxRuns: Int,
    toolFilter: ToolType? = null,
    failuresOnly: Boolean = false,
    generatedAtEpochMillis: Long = System.currentTimeMillis(),
): String {
    val filteredRuns = runs.asSequence()
        .filter { run -> toolFilter == null || run.tool == toolFilter }
        .filter { run -> !failuresOnly || run.status == RunStatus.FAILED }
        .take(maxRuns.coerceAtLeast(1))
        .map(ScanRunSummary::toExecutionReportItem)
        .toList()

    return ExecutionReportRenderer.render(
        format = format,
        title = title,
        items = filteredRuns,
        generatedAtEpochMillis = generatedAtEpochMillis,
    )
}

private fun ScanRunSummary.toExecutionReportItem(): ExecutionReportItem = ExecutionReportItem(
    profileName = profileName,
    tool = tool,
    route = route,
    status = status,
    trigger = trigger,
    commandPreview = commandPreview,
    message = message,
    startedAtEpochMillis = startedAtEpochMillis,
    finishedAtEpochMillis = finishedAtEpochMillis,
    parseSource = parsedSummary.parseSource,
    overview = parsedSummary.overview,
    observedHosts = parsedSummary.observedHosts,
    portFindings = parsedSummary.portFindings,
    newOpenPorts = newOpenPorts,
    closedPorts = closedPorts,
    warnings = parsedSummary.warnings,
    requestId = requestId,
    executorLabel = executorLabel,
)
