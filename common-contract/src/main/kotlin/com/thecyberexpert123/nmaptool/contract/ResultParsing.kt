package com.thecyberexpert123.nmaptool.contract

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
    val highlights: List<String> = emptyList(),
    val portFindings: List<PortFinding> = emptyList(),
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
    ): ToolResultSummary = when (tool) {
        ToolType.NMAP -> parseNmap(status = status, exitCode = exitCode, stdout = stdout, stderr = stderr)
        ToolType.NPING -> parseNping(status = status, exitCode = exitCode, stdout = stdout, stderr = stderr)
        ToolType.NCAT -> parseNcat(status = status, exitCode = exitCode, stdout = stdout, stderr = stderr)
    }

    private fun parseNmap(
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
    ): ToolResultSummary {
        val lines = stdout.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
        var currentHost: String? = null
        var reportedHosts = 0
        var upHosts = 0
        var scannedHosts: Int? = null
        var duration: String? = null
        val highlights = linkedSetOf<String>()
        val findings = mutableListOf<PortFinding>()

        lines.forEach { line ->
            when {
                nmapHostRegex.matches(line) -> {
                    currentHost = nmapHostRegex.matchEntire(line)?.groupValues?.get(1)?.trim()
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
            highlights = highlights.take(4),
            portFindings = findings.take(24),
        )
    }

    private fun parseNping(
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
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

        val overview = when (status) {
            RunStatus.SUCCEEDED -> packetSummary?.let { summary ->
                if (avgRtt != null) "$summary, avg RTT $avgRtt" else summary
            } ?: "Nping completed; inspect output for packet details."

            RunStatus.BLOCKED -> "Nping run was blocked before execution."
            RunStatus.FAILED -> "Nping failed${exitCode?.let { " with exit code $it" } ?: ""}."
        }

        return ToolResultSummary(
            overview = overview,
            highlights = highlights.take(4),
        )
    }

    private fun parseNcat(
        status: RunStatus,
        exitCode: Int?,
        stdout: String,
        stderr: String,
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
            highlights = highlights.distinct().take(4),
        )
    }
}
