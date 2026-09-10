package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResultDiffingTest {
    @Test
    fun `nmap delta analyzer reports new and missing open ports`() {
        val previous = ToolResultSummary(
            overview = "previous",
            portFindings = listOf(
                PortFinding(host = "host-a", port = 22, protocol = "tcp", state = "open", service = "ssh"),
                PortFinding(host = "host-a", port = 80, protocol = "tcp", state = "open", service = "http"),
            ),
        )
        val current = ToolResultSummary(
            overview = "current",
            portFindings = listOf(
                PortFinding(host = "host-a", port = 80, protocol = "tcp", state = "open", service = "http"),
                PortFinding(host = "host-a", port = 443, protocol = "tcp", state = "open", service = "https"),
            ),
        )

        val delta = ToolResultDeltaAnalyzer.compare(
            tool = ToolType.NMAP,
            previous = previous,
            current = current,
        )

        assertEquals(1, delta.newOpenPorts.size)
        assertEquals(443, delta.newOpenPorts.single().port)
        assertEquals(1, delta.closedPorts.size)
        assertEquals(22, delta.closedPorts.single().port)
        assertTrue(delta.summary.contains("1 new open port"))
        assertTrue(delta.summary.contains("1 previously open port no longer present"))
    }

    @Test
    fun `nmap delta analyzer reports unchanged open-port set`() {
        val summary = ToolResultSummary(
            overview = "same",
            portFindings = listOf(
                PortFinding(host = "host-a", port = 22, protocol = "tcp", state = "open", service = "ssh"),
            ),
        )

        val delta = ToolResultDeltaAnalyzer.compare(
            tool = ToolType.NMAP,
            previous = summary,
            current = summary,
        )

        assertEquals("No open-port delta detected since the previous Nmap run.", delta.summary)
        assertTrue(delta.newOpenPorts.isEmpty())
        assertTrue(delta.closedPorts.isEmpty())
    }

    @Test
    fun `non nmap tools return generic delta summary`() {
        val delta = ToolResultDeltaAnalyzer.compare(
            tool = ToolType.NPING,
            previous = null,
            current = ToolResultSummary(overview = "nping"),
        )

        assertEquals("No specialized delta analysis for nping output yet.", delta.summary)
    }
}
