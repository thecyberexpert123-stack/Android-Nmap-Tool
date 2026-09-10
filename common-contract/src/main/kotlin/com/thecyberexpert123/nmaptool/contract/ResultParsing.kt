package com.thecyberexpert123.nmaptool.contract

import org.w3c.dom.Element
import org.w3c.dom.NodeList
import org.xml.sax.InputSource
import java.io.StringReader
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory

private val nmapHostRegex = Regex("^Nmap scan report for (.+)$")
private val nmapHostUpRegex = Regex("^Host is up(?: \\(([^)]+) latency\\))?\\.$")
private val nmapPortRegex =
    Regex("^(\\d+)/(tcp|udp|sctp)\\s+(open(?:\\|filtered)?|closed(?:\\|filtered)?|filtered|unfiltered)\\s+(\\S+)(?:\\s+(.*))?$")
private val nmapDoneRegex = Regex("^Nmap done: (\\d+) IP addresses \\((\\d+) hosts up\\) scanned in (.+)$")
private val nmapNotShownRegex = Regex("^Not shown: (.+)$")
private val npingRttRegex = Regex("^Max rtt: (.+) \\| Min rtt: (.+) \\| Avg rtt: (.+)$", RegexOption.IGNORE_CASE)
private val npingPacketsRegex = Regex("^Raw packets sent: (.+) \\| Rcvd: (.+) \\| Lost: (.+)$", RegexOption.IGNORE_CASE)
private val ncatConnectedRegex = Regex("^(?:Ncat: )?Connected to (.+)$", RegexOption.IGNORE_CASE)

data class ToolResultSummary(
    val overview: String,
    val parseSource: ResultParseSource = ResultParseSource.NONE,
    val highlights: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val portFindings: List<PortFinding> = emptyList(),
    val observedHosts: List<String> = emptyList(),
)

data class PortFinding(
    val host: String?,
    val port: Int,
    val protocol: String,
    val state: String,
    val service: String,
    val details: String = "",
) {
    val endpointLabel: String
        get() = "$port/$protocol"
}

object ToolResultParser {
    fun parse(
        tool: ToolType,
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
        nmapXmlOutput: String? = null,
        stdoutTruncated: Boolean = false,
        stderrTruncated: Boolean = false,
        nmapXmlOutputTruncated: Boolean = false,
    ): ToolResultSummary = when (tool) {
        ToolType.NMAP -> parseNmap(
            status = status,
            exitCode = exitCode,
            stdout = stdout,
            stderr = stderr,
            nmapXmlOutput = nmapXmlOutput,
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
            nmapXmlOutputTruncated = nmapXmlOutputTruncated,
        )
        ToolType.NPING -> parseNping(
            status = status,
            exitCode = exitCode,
            stdout = stdout,
            stderr = stderr,
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
        )
        ToolType.NCAT -> parseNcat(
            status = status,
            exitCode = exitCode,
            stdout = stdout,
            stderr = stderr,
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
        )
    }

    private fun parseNmap(
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
        nmapXmlOutput: String?,
        stdoutTruncated: Boolean,
        stderrTruncated: Boolean,
        nmapXmlOutputTruncated: Boolean,
    ): ToolResultSummary {
        val xmlSummary = nmapXmlOutput
            ?.takeIf { it.isNotBlank() }
            ?.let { xml ->
                runCatching {
                    parseNmapXml(
                        status = status,
                        exitCode = exitCode,
                        xmlOutput = xml,
                        stderr = stderr,
                        stdoutTruncated = stdoutTruncated,
                        stderrTruncated = stderrTruncated,
                    )
                }.getOrNull()
            }
        return xmlSummary ?: parseNmapText(
            status = status,
            exitCode = exitCode,
            stdout = stdout,
            stderr = stderr,
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
            nmapXmlOutputTruncated = nmapXmlOutputTruncated,
        )
    }

    private fun parseNmapText(
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
        stdoutTruncated: Boolean,
        stderrTruncated: Boolean,
        nmapXmlOutputTruncated: Boolean,
    ): ToolResultSummary {
        val lines = stdout.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
        var currentHost: String? = null
        var reportedHosts = 0
        var upHosts = 0
        var scannedHosts: Int? = null
        var duration: String? = null
        val highlights = linkedSetOf<String>()
        val warnings = mutableListOf<String>()
        val findings = mutableListOf<PortFinding>()
        val observedHosts = linkedSetOf<String>()

        lines.forEach { line ->
            when {
                nmapHostRegex.matches(line) -> {
                    currentHost = nmapHostRegex.matchEntire(line)?.groupValues?.get(1)?.trim()
                    currentHost?.takeIf(String::isNotBlank)?.let(observedHosts::add)
                    reportedHosts += 1
                }

                nmapHostUpRegex.matches(line) -> {
                    upHosts += 1
                    nmapHostUpRegex.matchEntire(line)?.groupValues?.getOrNull(1)
                        ?.takeIf(String::isNotBlank)
                        ?.let { latency -> highlights += "Latency observed: $latency" }
                }

                nmapNotShownRegex.matches(line) -> {
                    nmapNotShownRegex.matchEntire(line)?.groupValues?.get(1)?.let { summary ->
                        highlights += "Not shown: $summary"
                    }
                }

                nmapPortRegex.matches(line) -> {
                    val match = nmapPortRegex.matchEntire(line) ?: return@forEach
                    val stateValue = match.groupValues[3]
                    if (!stateValue.startsWith("open")) {
                        return@forEach
                    }
                    findings += PortFinding(
                        host = currentHost,
                        port = match.groupValues[1].toIntOrNull() ?: return@forEach,
                        protocol = match.groupValues[2],
                        state = stateValue,
                        service = match.groupValues[4],
                        details = match.groupValues.getOrElse(5) { "" }.trim(),
                    )
                }

                nmapDoneRegex.matches(line) -> {
                    val match = nmapDoneRegex.matchEntire(line) ?: return@forEach
                    scannedHosts = match.groupValues[1].toIntOrNull()
                    upHosts = match.groupValues[2].toIntOrNull() ?: upHosts
                    duration = match.groupValues[3]
                }
            }
        }

        duration?.let { highlights += "Scan duration: $it" }
        if (stderr.isNotBlank() && status != RunStatus.SUCCEEDED) {
            highlights += "stderr captured during failed execution"
        }
        warnings += buildCaptureWarnings(
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
            nmapXmlOutputTruncated = nmapXmlOutputTruncated,
            xmlPreferred = true,
        )

        val hostSummary = when {
            scannedHosts != null -> "$upHosts of $scannedHosts hosts up"
            upHosts > 0 -> "$upHosts hosts up"
            reportedHosts > 0 -> "$reportedHosts hosts reported"
            else -> "No host summary parsed"
        }
        val portSummary = if (findings.isEmpty()) {
            "no open ports parsed"
        } else {
            "${findings.size} open/open-filtered ports parsed"
        }
        val overview = when (status) {
            RunStatus.SUCCEEDED -> "$hostSummary, $portSummary"
            RunStatus.BLOCKED -> "Nmap run was blocked before execution."
            RunStatus.FAILED -> "Nmap failed${exitCode?.let { " with exit code $it" } ?: ""}; $hostSummary, $portSummary"
        }

        return ToolResultSummary(
            overview = overview,
            parseSource = ResultParseSource.HEURISTIC_TEXT,
            highlights = highlights.take(4),
            warnings = warnings.take(4),
            portFindings = findings.take(24),
            observedHosts = observedHosts.take(24),
        )
    }

    private fun parseNmapXml(
        status: RunStatus,
        exitCode: Int?,
        xmlOutput: String,
        stderr: String,
        stdoutTruncated: Boolean,
        stderrTruncated: Boolean,
    ): ToolResultSummary {
        val documentBuilderFactory = createSecureDocumentBuilderFactory()
        val documentBuilder = documentBuilderFactory.newDocumentBuilder()
        val document = documentBuilder.parse(InputSource(StringReader(xmlOutput)))
        val hostNodes = document.getElementsByTagName("host")
        val findings = mutableListOf<PortFinding>()
        val observedHosts = linkedSetOf<String>()
        val highlights = linkedSetOf<String>()
        val warnings = mutableListOf<String>()
        var upHosts = 0

        hostNodes.asElements().forEach { hostElement ->
            val hostStatus = hostElement.firstElementByTagName("status")?.getAttribute("state").orEmpty()
            val hostLabel = hostElement.resolvePreferredHostLabel()
            if (hostStatus == "up") {
                upHosts += 1
            }
            hostLabel?.takeIf(String::isNotBlank)?.let(observedHosts::add)

            hostElement.firstElementByTagName("extraports")?.let { extraports ->
                val count = extraports.getAttribute("count")
                val stateName = extraports.getAttribute("state")
                if (count.isNotBlank() && stateName.isNotBlank()) {
                    highlights += "Not shown: $count $stateName ports"
                }
            }

            hostElement.getElementsByTagName("port").asElements().forEach { portElement ->
                val stateElement = portElement.firstElementByTagName("state") ?: return@forEach
                val stateValue = stateElement.getAttribute("state")
                if (!stateValue.startsWith("open")) {
                    return@forEach
                }
                val serviceElement = portElement.firstElementByTagName("service")
                findings += PortFinding(
                    host = hostLabel,
                    port = portElement.getAttribute("portid").toIntOrNull() ?: return@forEach,
                    protocol = portElement.getAttribute("protocol"),
                    state = stateValue,
                    service = serviceElement?.getAttribute("name").orEmpty().ifBlank { "unknown" },
                    details = buildString {
                        serviceElement?.getAttribute("product")?.takeIf(String::isNotBlank)?.let(::append)
                        serviceElement?.getAttribute("version")?.takeIf(String::isNotBlank)?.let { version ->
                            if (isNotEmpty()) append(' ')
                            append(version)
                        }
                        serviceElement?.getAttribute("extrainfo")?.takeIf(String::isNotBlank)?.let { extraInfo ->
                            if (isNotEmpty()) append(' ')
                            append(extraInfo)
                        }
                    }.trim(),
                )
            }
        }

        val runStatsHosts = document.getElementsByTagName("hosts").asElements().firstOrNull()
        val scannedHosts = runStatsHosts?.getAttribute("total")?.toIntOrNull()
        val reportedUpHosts = runStatsHosts?.getAttribute("up")?.toIntOrNull() ?: upHosts
        val elapsedSeconds = document.getElementsByTagName("finished").asElements().firstOrNull()
            ?.getAttribute("elapsed")
            ?.takeIf(String::isNotBlank)
        elapsedSeconds?.let { highlights += "Scan duration: ${it}s" }
        highlights += "Parsed from structured Nmap XML output"
        if (stderr.isNotBlank() && status != RunStatus.SUCCEEDED) {
            highlights += "stderr captured during failed execution"
        }
        warnings += buildCaptureWarnings(
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
            nmapXmlOutputTruncated = false,
            xmlPreferred = false,
        )

        val hostSummary = when {
            scannedHosts != null -> "$reportedUpHosts of $scannedHosts hosts up"
            reportedUpHosts > 0 -> "$reportedUpHosts hosts up"
            observedHosts.isNotEmpty() -> "${observedHosts.size} hosts reported"
            else -> "No host summary parsed"
        }
        val portSummary = if (findings.isEmpty()) {
            "no open ports parsed"
        } else {
            "${findings.size} open/open-filtered ports parsed"
        }
        val overview = when (status) {
            RunStatus.SUCCEEDED -> "$hostSummary, $portSummary"
            RunStatus.BLOCKED -> "Nmap run was blocked before execution."
            RunStatus.FAILED -> "Nmap failed${exitCode?.let { " with exit code $it" } ?: ""}; $hostSummary, $portSummary"
        }

        return ToolResultSummary(
            overview = overview,
            parseSource = ResultParseSource.STRUCTURED_NMAP_XML,
            highlights = highlights.take(5),
            warnings = warnings.take(4),
            portFindings = findings.take(48),
            observedHosts = observedHosts.take(48),
        )
    }

    private fun parseNping(
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
        stdoutTruncated: Boolean,
        stderrTruncated: Boolean,
    ): ToolResultSummary {
        val lines = stdout.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
        var avgRtt: String? = null
        var packetSummary: String? = null
        val highlights = mutableListOf<String>()

        lines.forEach { line ->
            when {
                npingRttRegex.matches(line) -> {
                    val match = npingRttRegex.matchEntire(line) ?: return@forEach
                    highlights += "RTT min ${match.groupValues[2]}, avg ${match.groupValues[3]}, max ${match.groupValues[1]}"
                    avgRtt = match.groupValues[3]
                }

                npingPacketsRegex.matches(line) -> {
                    val match = npingPacketsRegex.matchEntire(line) ?: return@forEach
                    packetSummary = "Sent ${match.groupValues[1]}, received ${match.groupValues[2]}, lost ${match.groupValues[3]}"
                    highlights += packetSummary!!
                }
            }
        }

        if (stderr.isNotBlank() && status != RunStatus.SUCCEEDED) {
            highlights += "stderr captured during failed execution"
        }
        val warnings = buildCaptureWarnings(
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
            nmapXmlOutputTruncated = false,
            xmlPreferred = false,
        )

        val overview = when (status) {
            RunStatus.SUCCEEDED -> packetSummary?.let { summary ->
                if (avgRtt != null) "$summary, avg RTT $avgRtt" else summary
            } ?: "Nping completed; inspect output for packet details."

            RunStatus.BLOCKED -> "Nping run was blocked before execution."
            RunStatus.FAILED -> "Nping failed${exitCode?.let { " with exit code $it" } ?: ""}."
        }

        return ToolResultSummary(
            overview = overview,
            parseSource = if (stdout.isBlank() && stderr.isBlank()) ResultParseSource.NONE else ResultParseSource.HEURISTIC_TEXT,
            highlights = highlights.take(4),
            warnings = warnings.take(4),
        )
    }

    private fun parseNcat(
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
        stdoutTruncated: Boolean,
        stderrTruncated: Boolean,
    ): ToolResultSummary {
        val combinedLines = sequenceOf(stdout, stderr)
            .flatMap { text -> text.lineSequence() }
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toList()
        val highlights = mutableListOf<String>()

        combinedLines.firstOrNull { ncatConnectedRegex.matches(it) }
            ?.let { line ->
                val target = ncatConnectedRegex.matchEntire(line)?.groupValues?.get(1).orEmpty()
                highlights += "Connected to $target"
            }

        stdout.lineSequence().map(String::trim).firstOrNull(String::isNotEmpty)
            ?.let { firstOutput -> highlights += "Output: ${firstOutput.take(120)}" }
        val warnings = buildCaptureWarnings(
            stdoutTruncated = stdoutTruncated,
            stderrTruncated = stderrTruncated,
            nmapXmlOutputTruncated = false,
            xmlPreferred = false,
        )

        val overview = when (status) {
            RunStatus.SUCCEEDED -> if (combinedLines.isEmpty()) {
                "Ncat completed without captured output."
            } else {
                "Ncat completed with captured session output."
            }

            RunStatus.BLOCKED -> "Ncat run was blocked before execution."
            RunStatus.FAILED -> "Ncat failed${exitCode?.let { " with exit code $it" } ?: ""}."
        }

        return ToolResultSummary(
            overview = overview,
            parseSource = if (combinedLines.isEmpty()) ResultParseSource.NONE else ResultParseSource.HEURISTIC_TEXT,
            highlights = highlights.distinct().take(4),
            warnings = warnings.take(4),
        )
    }

    private fun buildCaptureWarnings(
        stdoutTruncated: Boolean,
        stderrTruncated: Boolean,
        nmapXmlOutputTruncated: Boolean,
        xmlPreferred: Boolean,
    ): List<String> = buildList {
        if (stdoutTruncated) {
            add("Captured standard output was truncated; parsed findings may be incomplete.")
        }
        if (stderrTruncated) {
            add("Captured standard error was truncated; failure details may be incomplete.")
        }
        if (nmapXmlOutputTruncated) {
            add(
                if (xmlPreferred) {
                    "Structured Nmap XML exceeded the capture limit, so parsing fell back to normal text output."
                } else {
                    "Structured Nmap XML exceeded the capture limit and was omitted from the saved response."
                },
            )
        }
    }

    private fun createSecureDocumentBuilderFactory(): DocumentBuilderFactory =
        DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = false
            isXIncludeAware = false
            setExpandEntityReferences(false)
            runCatching { setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) }
            runCatching { setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false) }
            runCatching { setFeature("http://xml.org/sax/features/external-general-entities", false) }
            runCatching { setFeature("http://xml.org/sax/features/external-parameter-entities", false) }
            runCatching { setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "") }
            runCatching { setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "") }
        }

    private fun NodeList.asElements(): List<Element> =
        buildList {
            for (index in 0 until length) {
                val node = item(index)
                if (node is Element) {
                    add(node)
                }
            }
        }

    private fun Element.firstElementByTagName(name: String): Element? =
        getElementsByTagName(name).asElements().firstOrNull()

    private fun Element.resolvePreferredHostLabel(): String? {
        val hostname = getElementsByTagName("hostname").asElements().firstOrNull()
            ?.getAttribute("name")
            ?.trim()
            .orEmpty()
        if (hostname.isNotBlank()) {
            return hostname
        }

        val addresses = getElementsByTagName("address").asElements()
        val preferredAddress = addresses.firstOrNull { address ->
            address.getAttribute("addrtype") == "ipv4"
        } ?: addresses.firstOrNull { address ->
            address.getAttribute("addrtype") == "ipv6"
        } ?: addresses.firstOrNull()

        return preferredAddress?.getAttribute("addr")?.trim()?.takeIf(String::isNotBlank)
    }
}
