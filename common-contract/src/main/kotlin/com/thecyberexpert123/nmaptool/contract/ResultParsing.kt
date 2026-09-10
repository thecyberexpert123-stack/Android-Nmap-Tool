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
private val nmapDeviceTypeRegex = Regex("^Device type: (.+)$")
private val nmapOsDetailsRegex = Regex("^OS details: (.+)$")
private val nmapOsEvidenceRegex = Regex("^OS fingerprint evidence: (.+)$")
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
    val hostDetails: List<HostDetail> = emptyList(),
    val scriptFindings: List<ScriptFinding> = emptyList(),
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

data class HostDetail(
    val host: String,
    val status: String = "",
    val summaryLines: List<String> = emptyList(),
)

data class ScriptFinding(
    val scriptId: String,
    val output: String,
    val host: String? = null,
    val port: Int? = null,
    val protocol: String? = null,
    val scope: String = "host",
) {
    val locationLabel: String
        get() = when {
            port != null && !protocol.isNullOrBlank() -> listOfNotNull(host?.takeIf(String::isNotBlank), "$port/$protocol").joinToString(" ")
            !host.isNullOrBlank() -> host.orEmpty()
            else -> scope
        }
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
        val xmlCandidate = nmapXmlOutput?.takeIf { it.isNotBlank() }
        if (xmlCandidate != null) {
            val xmlResult = runCatching {
                parseNmapXml(
                    status = status,
                    exitCode = exitCode,
                    xmlOutput = xmlCandidate,
                    stderr = stderr,
                    stdoutTruncated = stdoutTruncated,
                    stderrTruncated = stderrTruncated,
                )
            }
            xmlResult.getOrNull()?.let { return it }

            val fallback = parseNmapText(
                status = status,
                exitCode = exitCode,
                stdout = stdout,
                stderr = stderr,
                stdoutTruncated = stdoutTruncated,
                stderrTruncated = stderrTruncated,
                nmapXmlOutputTruncated = nmapXmlOutputTruncated,
            )
            return fallback.copy(
                warnings = (
                    listOf("Structured Nmap XML was present but could not be parsed securely, so parsing fell back to normal text output.") +
                        fallback.warnings
                    ).distinct().take(5),
            )
        }

        return parseNmapText(
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
        val hostDetailsByLabel = linkedMapOf<String, MutableHostDetail>()

        lines.forEach { line ->
            when {
                nmapHostRegex.matches(line) -> {
                    currentHost = nmapHostRegex.matchEntire(line)?.groupValues?.get(1)?.trim()
                    currentHost?.takeIf(String::isNotBlank)?.let { hostLabel ->
                        observedHosts += hostLabel
                        hostDetailsByLabel.getOrPut(hostLabel) { MutableHostDetail(host = hostLabel) }
                    }
                    reportedHosts += 1
                }

                nmapHostUpRegex.matches(line) -> {
                    upHosts += 1
                    currentHost?.let { hostLabel ->
                        hostDetailsByLabel.getOrPut(hostLabel) { MutableHostDetail(host = hostLabel) }.status = "up"
                    }
                    nmapHostUpRegex.matchEntire(line)?.groupValues?.getOrNull(1)
                        ?.takeIf(String::isNotBlank)
                        ?.let { latency ->
                            highlights += "Latency observed: $latency"
                            currentHost?.let { hostLabel ->
                                hostDetailsByLabel.getOrPut(hostLabel) { MutableHostDetail(host = hostLabel) }
                                    .summaryLines += "Latency: $latency"
                            }
                        }
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

                nmapDeviceTypeRegex.matches(line) -> {
                    nmapDeviceTypeRegex.matchEntire(line)?.groupValues?.get(1)?.takeIf(String::isNotBlank)?.let { deviceType ->
                        highlights += "Device type: $deviceType"
                        currentHost?.let { hostLabel ->
                            hostDetailsByLabel.getOrPut(hostLabel) { MutableHostDetail(host = hostLabel) }
                                .summaryLines += "Device type: $deviceType"
                        }
                    }
                }

                nmapOsDetailsRegex.matches(line) -> {
                    nmapOsDetailsRegex.matchEntire(line)?.groupValues?.get(1)?.takeIf(String::isNotBlank)?.let { osDetails ->
                        highlights += "OS details: $osDetails"
                        currentHost?.let { hostLabel ->
                            hostDetailsByLabel.getOrPut(hostLabel) { MutableHostDetail(host = hostLabel) }
                                .summaryLines += "OS details: $osDetails"
                        }
                    }
                }

                nmapOsEvidenceRegex.matches(line) -> {
                    nmapOsEvidenceRegex.matchEntire(line)?.groupValues?.get(1)?.takeIf(String::isNotBlank)?.let { evidence ->
                        highlights += "OS fingerprint evidence: $evidence"
                        currentHost?.let { hostLabel ->
                            hostDetailsByLabel.getOrPut(hostLabel) { MutableHostDetail(host = hostLabel) }
                                .summaryLines += "OS fingerprint evidence: $evidence"
                        }
                    }
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
            highlights = highlights.take(6),
            warnings = warnings.take(5),
            portFindings = findings.take(24),
            observedHosts = observedHosts.take(24),
            hostDetails = hostDetailsByLabel.values
                .map(MutableHostDetail::toImmutable)
                .filter { it.summaryLines.isNotEmpty() }
                .take(24),
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
        val hostDetails = mutableListOf<HostDetail>()
        val scriptFindings = mutableListOf<ScriptFinding>()
        var upHosts = 0

        hostNodes.asElements().forEach { hostElement ->
            val hostStatus = hostElement.firstChildElementByTagName("status")?.getAttribute("state").orEmpty()
            val hostLabel = hostElement.resolvePreferredHostLabel()
            if (hostStatus == "up") {
                upHosts += 1
            }
            hostLabel?.takeIf(String::isNotBlank)?.let(observedHosts::add)

            val hostDetailLines = linkedSetOf<String>()
            val hostnames = hostElement.firstChildElementByTagName("hostnames")
                ?.childElementsByTagName("hostname")
                ?.mapNotNull { hostname -> hostname.getAttribute("name").trim().takeIf(String::isNotBlank) }
                .orEmpty()
            val addresses = hostElement.childElementsByTagName("address")
                .mapNotNull { address ->
                    address.getAttribute("addr").trim().takeIf(String::isNotBlank)?.let { value ->
                        buildString {
                            append(value)
                            address.getAttribute("addrtype").trim().takeIf(String::isNotBlank)?.let { type ->
                                append(" (")
                                append(type)
                                address.getAttribute("vendor").trim().takeIf(String::isNotBlank)?.let { vendor ->
                                    append(", ")
                                    append(vendor)
                                }
                                append(')')
                            }
                        }
                    }
                }
            if (addresses.isNotEmpty()) {
                hostDetailLines += "Addresses: ${addresses.joinToString(separator = ", ")}"
            }
            if (hostnames.isNotEmpty()) {
                val alternativeNames = hostnames.filterNot { it == hostLabel }
                if (alternativeNames.isNotEmpty()) {
                    hostDetailLines += "Additional names: ${alternativeNames.joinToString(separator = ", ")}"
                }
            }

            val portsElement = hostElement.firstChildElementByTagName("ports")
            portsElement?.firstChildElementByTagName("extraports")?.let { extraports ->
                val count = extraports.getAttribute("count")
                val stateName = extraports.getAttribute("state")
                if (count.isNotBlank() && stateName.isNotBlank()) {
                    val summary = "Not shown: $count $stateName ports"
                    highlights += summary
                    hostDetailLines += summary
                }
            }

            hostElement.firstChildElementByTagName("os")?.let { osElement ->
                val bestMatch = osElement.childElementsByTagName("osmatch").firstOrNull()
                bestMatch?.getAttribute("name")?.trim()?.takeIf(String::isNotBlank)?.let { matchName ->
                    val accuracy = bestMatch.getAttribute("accuracy").trim()
                    val osMatchSummary = if (accuracy.isNotBlank()) {
                        "OS match: $matchName (accuracy $accuracy)"
                    } else {
                        "OS match: $matchName"
                    }
                    highlights += osMatchSummary
                    hostDetailLines += osMatchSummary
                }
                bestMatch?.childElementsByTagName("osclass")?.firstOrNull()?.let { osClass ->
                    val osClassSummary = buildString {
                        osClass.getAttribute("type").trim().takeIf(String::isNotBlank)?.let {
                            append("Device type: ")
                            append(it)
                        }
                        osClass.getAttribute("vendor").trim().takeIf(String::isNotBlank)?.let { vendor ->
                            if (isNotEmpty()) append("; ")
                            append("Vendor: ")
                            append(vendor)
                        }
                        osClass.getAttribute("osfamily").trim().takeIf(String::isNotBlank)?.let { family ->
                            if (isNotEmpty()) append("; ")
                            append("OS family: ")
                            append(family)
                        }
                        osClass.getAttribute("osgen").trim().takeIf(String::isNotBlank)?.let { generation ->
                            if (isNotEmpty()) append("; ")
                            append("OS generation: ")
                            append(generation)
                        }
                    }.trim()
                    if (osClassSummary.isNotBlank()) {
                        hostDetailLines += osClassSummary
                    }
                }
                osElement.childElementsByTagName("osfingerprint").firstOrNull()
                    ?.getAttribute("fingerprint")
                    ?.trim()
                    ?.takeIf(String::isNotBlank)
                    ?.let { fingerprint ->
                        hostDetailLines += "OS fingerprint: ${fingerprint.truncateWithEllipsis(180)}"
                    }
            }

            hostElement.firstChildElementByTagName("uptime")?.let { uptime ->
                val seconds = uptime.getAttribute("seconds").trim()
                val lastBoot = uptime.getAttribute("lastboot").trim()
                val uptimeSummary = buildString {
                    if (seconds.isNotBlank()) {
                        append("Uptime: ")
                        append(seconds)
                        append(" seconds")
                    }
                    if (lastBoot.isNotBlank()) {
                        if (isNotEmpty()) append("; ")
                        append("Last boot: ")
                        append(lastBoot)
                    }
                }
                if (uptimeSummary.isNotBlank()) {
                    hostDetailLines += uptimeSummary
                }
            }

            hostElement.firstChildElementByTagName("distance")?.getAttribute("value")?.trim()?.takeIf(String::isNotBlank)?.let { distance ->
                hostDetailLines += "Network distance: $distance hops"
            }

            val traceHops = hostElement.firstChildElementByTagName("trace")
                ?.childElementsByTagName("hop")
                .orEmpty()
                .mapNotNull { hop ->
                    hop.getAttribute("ttl").trim().toIntOrNull()?.let { ttl ->
                        TracerouteHop(
                            ttl = ttl,
                            ipAddress = hop.getAttribute("ipaddr").trim().takeIf(String::isNotBlank),
                            host = hop.getAttribute("host").trim().takeIf(String::isNotBlank),
                            rtt = hop.getAttribute("rtt").trim().takeIf(String::isNotBlank),
                        )
                    }
                }
            if (traceHops.isNotEmpty()) {
                val lastHop = traceHops.maxByOrNull { it.ttl }
                hostDetailLines += buildString {
                    append("Traceroute: ")
                    append(traceHops.size)
                    append(" hops captured")
                    lastHop?.let { hop ->
                        append("; last hop ")
                        append(formatTraceHop(hop))
                    }
                }
            }

            scriptFindings += extractScriptFindings(
                scriptsContainer = hostElement.firstChildElementByTagName("hostscript"),
                host = hostLabel,
                scope = "hostscript",
            )

            portsElement
                ?.childElementsByTagName("port")
                .orEmpty()
                .forEach { portElement ->
                    val stateElement = portElement.firstChildElementByTagName("state") ?: return@forEach
                    val stateValue = stateElement.getAttribute("state")
                    if (!stateValue.startsWith("open")) {
                        return@forEach
                    }
                    val serviceElement = portElement.firstChildElementByTagName("service")
                    val portNumber = portElement.getAttribute("portid").toIntOrNull() ?: return@forEach
                    val protocol = portElement.getAttribute("protocol")
                    findings += PortFinding(
                        host = hostLabel,
                        port = portNumber,
                        protocol = protocol,
                        state = stateValue,
                        service = serviceElement?.getAttribute("name").orEmpty().ifBlank { "unknown" },
                        details = buildServiceDetails(serviceElement),
                    )
                    scriptFindings += extractScriptFindings(
                        scriptsContainer = portElement,
                        host = hostLabel,
                        port = portNumber,
                        protocol = protocol,
                        scope = "portscript",
                    )
                }

            val hostDetailLabel = hostLabel?.takeIf(String::isNotBlank)
            if (hostDetailLabel != null && hostDetailLines.isNotEmpty()) {
                hostDetails += HostDetail(
                    host = hostDetailLabel,
                    status = hostStatus,
                    summaryLines = hostDetailLines.take(8),
                )
            }
        }

        scriptFindings += extractScriptFindings(
            scriptsContainer = document.documentElement.firstChildElementByTagName("prescript"),
            scope = "prescript",
        )
        scriptFindings += extractScriptFindings(
            scriptsContainer = document.documentElement.firstChildElementByTagName("postscript"),
            scope = "postscript",
        )

        val runStatsHosts = document.getElementsByTagName("hosts").asElements().firstOrNull()
        val scannedHosts = runStatsHosts?.getAttribute("total")?.toIntOrNull()
        val reportedUpHosts = runStatsHosts?.getAttribute("up")?.toIntOrNull() ?: upHosts
        val elapsedSeconds = document.getElementsByTagName("finished").asElements().firstOrNull()
            ?.getAttribute("elapsed")
            ?.takeIf(String::isNotBlank)
        elapsedSeconds?.let { highlights += "Scan duration: ${it}s" }
        highlights += "Parsed from structured Nmap XML output"
        if (scriptFindings.isNotEmpty()) {
            highlights += "Captured ${scriptFindings.size} script result${if (scriptFindings.size == 1) "" else "s"} from XML output"
        }
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
            highlights = highlights.take(6),
            warnings = warnings.take(5),
            portFindings = findings.take(48),
            observedHosts = observedHosts.take(48),
            hostDetails = hostDetails.take(24),
            scriptFindings = scriptFindings.distinct().take(48),
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

    private fun extractScriptFindings(
        scriptsContainer: Element?,
        host: String? = null,
        port: Int? = null,
        protocol: String? = null,
        scope: String,
    ): List<ScriptFinding> = scriptsContainer
        ?.childElementsByTagName("script")
        ?.mapNotNull { script ->
            val scriptId = script.getAttribute("id").trim().takeIf(String::isNotBlank) ?: return@mapNotNull null
            val output = normalizeInlineScriptOutput(script.getAttribute("output"))
            output.takeIf(String::isNotBlank)?.let {
                ScriptFinding(
                    scriptId = scriptId,
                    output = it,
                    host = host,
                    port = port,
                    protocol = protocol,
                    scope = scope,
                )
            }
        }
        .orEmpty()

    private fun buildServiceDetails(serviceElement: Element?): String {
        if (serviceElement == null) {
            return ""
        }
        val segments = mutableListOf<String>()
        buildString {
            serviceElement.getAttribute("product").trim().takeIf(String::isNotBlank)?.let(::append)
            serviceElement.getAttribute("version").trim().takeIf(String::isNotBlank)?.let { version ->
                if (isNotEmpty()) append(' ')
                append(version)
            }
            serviceElement.getAttribute("extrainfo").trim().takeIf(String::isNotBlank)?.let { extraInfo ->
                if (isNotEmpty()) append(' ')
                append(extraInfo)
            }
        }.trim().takeIf(String::isNotBlank)?.let(segments::add)
        serviceElement.getAttribute("tunnel").trim().takeIf(String::isNotBlank)?.let { segments += "tunnel: $it" }
        serviceElement.getAttribute("hostname").trim().takeIf(String::isNotBlank)?.let { segments += "hostname: $it" }
        serviceElement.getAttribute("ostype").trim().takeIf(String::isNotBlank)?.let { segments += "ostype: $it" }
        serviceElement.getAttribute("devicetype").trim().takeIf(String::isNotBlank)?.let { segments += "device: $it" }
        serviceElement.getAttribute("method").trim().takeIf(String::isNotBlank)?.let { segments += "method: $it" }
        serviceElement.getAttribute("conf").trim().takeIf(String::isNotBlank)?.let { segments += "confidence: $it" }
        val cpes = serviceElement.childElementsByTagName("cpe")
            .mapNotNull { cpe -> cpe.textContent?.trim()?.takeIf(String::isNotBlank) }
            .distinct()
        if (cpes.isNotEmpty()) {
            segments += "CPE: ${cpes.joinToString(separator = ", ")}".truncateWithEllipsis(200)
        }
        return segments.joinToString(separator = "; ")
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

    private fun Element.childElementsByTagName(name: String): List<Element> =
        childNodes.asElements().filter { it.tagName == name }

    private fun Element.firstChildElementByTagName(name: String): Element? =
        childElementsByTagName(name).firstOrNull()

    private fun Element.resolvePreferredHostLabel(): String? {
        val hostname = firstChildElementByTagName("hostnames")
            ?.childElementsByTagName("hostname")
            ?.firstOrNull()
            ?.getAttribute("name")
            ?.trim()
            .orEmpty()
        if (hostname.isNotBlank()) {
            return hostname
        }

        val addresses = childElementsByTagName("address")
        val preferredAddress = addresses.firstOrNull { address ->
            address.getAttribute("addrtype") == "ipv4"
        } ?: addresses.firstOrNull { address ->
            address.getAttribute("addrtype") == "ipv6"
        } ?: addresses.firstOrNull()

        return preferredAddress?.getAttribute("addr")?.trim()?.takeIf(String::isNotBlank)
    }

    private fun normalizeInlineScriptOutput(raw: String): String = raw
        .lineSequence()
        .map(String::trim)
        .filter(String::isNotEmpty)
        .joinToString(separator = " | ")
        .ifBlank { raw.trim() }
        .truncateWithEllipsis(240)

    private fun String.truncateWithEllipsis(maxLength: Int): String {
        if (length <= maxLength) {
            return this
        }
        return take(maxLength.coerceAtLeast(1)).trimEnd() + "…"
    }

    private fun formatTraceHop(hop: TracerouteHop): String = buildString {
        append("TTL ")
        append(hop.ttl)
        hop.host?.takeIf(String::isNotBlank)?.let {
            append(' ')
            append(it)
        }
        hop.ipAddress?.takeIf(String::isNotBlank)?.let {
            append(" (")
            append(it)
            append(')')
        }
        hop.rtt?.takeIf(String::isNotBlank)?.let {
            append(" RTT ")
            append(it)
            append(" ms")
        }
    }

    private data class MutableHostDetail(
        val host: String,
        var status: String = "",
        val summaryLines: LinkedHashSet<String> = linkedSetOf(),
    ) {
        fun toImmutable(): HostDetail = HostDetail(
            host = host,
            status = status,
            summaryLines = summaryLines.toList(),
        )
    }

    private data class TracerouteHop(
        val ttl: Int,
        val ipAddress: String? = null,
        val host: String? = null,
        val rtt: String? = null,
    )
}
