package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResultParsingTest {
    @Test
    fun `nmap parser extracts hosts and open ports from standard output`() {
        val stdout = """
            Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-10 15:10 UTC
            Nmap scan report for scanme.nmap.org (45.33.32.156)
            Host is up (0.12s latency).
            Not shown: 997 closed tcp ports (reset)
            PORT    STATE SERVICE VERSION
            22/tcp  open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
            80/tcp  open  http    Apache httpd 2.4.7
            9929/tcp open nping-echo Nping echo
            Nmap done: 1 IP addresses (1 hosts up) scanned in 18.42 seconds
        """.trimIndent()

        val summary = ToolResultParser.parse(
            tool = ToolType.NMAP,
            status = RunStatus.SUCCEEDED,
            exitCode = 0,
            stdout = stdout,
            stderr = "",
        )

        assertEquals("1 of 1 hosts up, 3 open/open-filtered ports parsed", summary.overview)
        assertEquals(3, summary.portFindings.size)
        assertEquals(22, summary.portFindings.first().port)
        assertTrue(summary.highlights.any { it.contains("Scan duration") })
    }

    @Test
    fun `nping parser extracts packet and latency summary`() {
        val stdout = """
            Raw packets sent: 5 (200B) | Rcvd: 5 (220B) | Lost: 0 (0.00%)
            Max rtt: 12.40ms | Min rtt: 10.30ms | Avg rtt: 11.21ms
        """.trimIndent()

        val summary = ToolResultParser.parse(
            tool = ToolType.NPING,
            status = RunStatus.SUCCEEDED,
            exitCode = 0,
            stdout = stdout,
            stderr = "",
        )

        assertEquals("Sent 5 (200B), received 5 (220B), lost 0 (0.00%), avg RTT 11.21ms", summary.overview)
        assertTrue(summary.highlights.any { it.contains("RTT min 10.30ms") })
    }

    @Test
    fun `ncat parser surfaces connection target when available`() {
        val stderr = "Ncat: Connected to 192.168.0.10:443."
        val stdout = "HTTP/1.1 200 OK"

        val summary = ToolResultParser.parse(
            tool = ToolType.NCAT,
            status = RunStatus.SUCCEEDED,
            exitCode = 0,
            stdout = stdout,
            stderr = stderr,
        )

        assertEquals("Ncat completed with captured session output.", summary.overview)
        assertTrue(summary.highlights.any { it.contains("Connected to 192.168.0.10:443") })
    }
}
