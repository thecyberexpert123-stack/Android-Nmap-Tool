package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResultParsingTest {
    @Test
    fun `nmap text parser extracts hosts and open ports from standard output`() {
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
        assertEquals(ResultParseSource.HEURISTIC_TEXT, summary.parseSource)
        assertEquals(3, summary.portFindings.size)
        assertEquals(22, summary.portFindings.first().port)
        assertTrue(summary.observedHosts.any { it.contains("scanme.nmap.org") })
        assertTrue(summary.highlights.any { it.contains("Scan duration") })
    }

    @Test
    fun `nmap xml parser extracts structured hosts and ports when available`() {
        val xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE nmaprun>
            <nmaprun scanner="nmap" args="nmap -oX - scanme.nmap.org" start="1725971400" version="7.95" xmloutputversion="1.05">
              <host starttime="1725971401" endtime="1725971410">
                <status state="up" reason="syn-ack" reason_ttl="0" />
                <address addr="45.33.32.156" addrtype="ipv4" />
                <hostnames>
                  <hostname name="scanme.nmap.org" type="user" />
                </hostnames>
                <ports>
                  <extraports state="closed" count="997" />
                  <port protocol="tcp" portid="22">
                    <state state="open" reason="syn-ack" reason_ttl="0" />
                    <service name="ssh" product="OpenSSH" version="8.2" extrainfo="Ubuntu" />
                  </port>
                  <port protocol="tcp" portid="80">
                    <state state="open" reason="syn-ack" reason_ttl="0" />
                    <service name="http" product="Apache httpd" version="2.4.57" />
                  </port>
                </ports>
              </host>
              <runstats>
                <finished time="1725971411" elapsed="11.23" summary="Nmap done" exit="success" />
                <hosts up="1" down="0" total="1" />
              </runstats>
            </nmaprun>
        """.trimIndent()

        val summary = ToolResultParser.parse(
            tool = ToolType.NMAP,
            status = RunStatus.SUCCEEDED,
            exitCode = 0,
            stdout = "interactive output suppressed",
            stderr = "",
            nmapXmlOutput = xml,
        )

        assertEquals("1 of 1 hosts up, 2 open/open-filtered ports parsed", summary.overview)
        assertEquals(ResultParseSource.STRUCTURED_NMAP_XML, summary.parseSource)
        assertEquals(listOf("scanme.nmap.org"), summary.observedHosts)
        assertEquals(2, summary.portFindings.size)
        assertTrue(summary.highlights.any { it.contains("structured Nmap XML") })
    }

    @Test
    fun `nmap text parser keeps android local curated service details`() {
        val stdout = """
            Nmap scan report for 192.168.1.10
            Host is up (18ms latency).
            PORT     STATE SERVICE VERSION
            22/tcp open ssh android-local sV: banner SSH-2.0-OpenSSH_8.4
            443/tcp open https android-local sV: TLS TLSv1.3; cipher TLS_AES_128_GCM_SHA256; HTTP/1.1 200 OK; Server: nginx
            Nmap done: 1 IP addresses (1 hosts up) scanned in 2.00 seconds
        """.trimIndent()

        val summary = ToolResultParser.parse(
            tool = ToolType.NMAP,
            status = RunStatus.SUCCEEDED,
            exitCode = 0,
            stdout = stdout,
            stderr = "",
        )

        assertEquals(ResultParseSource.HEURISTIC_TEXT, summary.parseSource)
        assertEquals(2, summary.portFindings.size)
        assertEquals("android-local sV: banner SSH-2.0-OpenSSH_8.4", summary.portFindings.first().details)
        assertTrue(summary.portFindings.any { it.service == "https" && it.details.contains("Server: nginx") })
    }

    @Test
    fun `nmap parser warns when structured xml is omitted because of capture limits`() {
        val stdout = """
            Nmap scan report for 192.168.1.10
            Host is up.
            PORT   STATE SERVICE
            443/tcp open  https
            Nmap done: 1 IP addresses (1 hosts up) scanned in 2.00 seconds
        """.trimIndent()

        val summary = ToolResultParser.parse(
            tool = ToolType.NMAP,
            status = RunStatus.SUCCEEDED,
            exitCode = 0,
            stdout = stdout,
            stderr = "",
            nmapXmlOutput = null,
            stdoutTruncated = false,
            stderrTruncated = false,
            nmapXmlOutputTruncated = true,
        )

        assertEquals(ResultParseSource.HEURISTIC_TEXT, summary.parseSource)
        assertTrue(summary.warnings.any { it.contains("fell back to normal text output") })
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
        assertEquals(ResultParseSource.HEURISTIC_TEXT, summary.parseSource)
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
        assertEquals(ResultParseSource.HEURISTIC_TEXT, summary.parseSource)
        assertTrue(summary.highlights.any { it.contains("Connected to 192.168.0.10:443") })
    }
}
