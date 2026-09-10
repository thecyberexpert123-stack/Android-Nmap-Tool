package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertTrue

class ReportRenderingTest {
    @Test
    fun `markdown report includes summary metadata and findings`() {
        val report = ExecutionReportRenderer.render(
            format = ReportExportFormat.MARKDOWN,
            title = "Android Nmap Tool Report",
            generatedAtEpochMillis = 1_725_972_000_000,
            items = listOf(
                ExecutionReportItem(
                    profileName = "Edge gateway",
                    tool = ToolType.NMAP,
                    route = ExecutionRoute.REMOTE,
                    status = RunStatus.SUCCEEDED,
                    trigger = RunTrigger.MANUAL,
                    commandPreview = "nmap -Pn -sV 192.168.1.1",
                    message = "Remote execution completed successfully.",
                    startedAtEpochMillis = 1_725_971_990_000,
                    finishedAtEpochMillis = 1_725_972_010_000,
                    parseSource = ResultParseSource.STRUCTURED_NMAP_XML,
                    overview = "1 of 1 hosts up, 2 open/open-filtered ports parsed",
                    observedHosts = listOf("192.168.1.1"),
                    portFindings = listOf(
                        PortFinding(host = "192.168.1.1", port = 22, protocol = "tcp", state = "open", service = "ssh"),
                    ),
                    newOpenPorts = listOf(
                        PortFinding(host = "192.168.1.1", port = 443, protocol = "tcp", state = "open", service = "https"),
                    ),
                    warnings = listOf("Captured standard output was truncated; parsed findings may be incomplete."),
                    requestId = "req-123",
                    executorLabel = "lab-executor",
                ),
            ),
        )

        assertTrue(report.contains("# Android Nmap Tool Report"))
        assertTrue(report.contains("Structured XML parsed runs: 1"))
        assertTrue(report.contains("Executor: lab-executor"))
        assertTrue(report.contains("Request ID: req-123"))
        assertTrue(report.contains("New open ports since previous run"))
        assertTrue(report.contains("192.168.1.1 443/tcp open https"))
    }

    @Test
    fun `csv report escapes fields and includes request identifiers`() {
        val report = ExecutionReportRenderer.render(
            format = ReportExportFormat.CSV,
            title = "unused",
            items = listOf(
                ExecutionReportItem(
                    profileName = "Prod, API",
                    tool = ToolType.NCAT,
                    route = ExecutionRoute.REMOTE,
                    status = RunStatus.FAILED,
                    trigger = RunTrigger.SCHEDULED,
                    commandPreview = "ncat -v api.example.com 443",
                    message = "HTTP 401: \"unauthorized\"",
                    startedAtEpochMillis = 1_725_971_990_000,
                    finishedAtEpochMillis = 1_725_971_995_000,
                    parseSource = ResultParseSource.HEURISTIC_TEXT,
                    overview = "Ncat failed with exit code 1.",
                    warnings = listOf("Captured standard error was truncated; failure details may be incomplete."),
                    requestId = "req-456",
                    executorLabel = "wan-edge",
                ),
            ),
        )

        assertTrue(report.lineSequence().first().contains("request_id"))
        assertTrue(report.contains("\"Prod, API\""))
        assertTrue(report.contains("req-456"))
        assertTrue(report.contains("\"HTTP 401: \"\"unauthorized\"\"\""))
    }
}
