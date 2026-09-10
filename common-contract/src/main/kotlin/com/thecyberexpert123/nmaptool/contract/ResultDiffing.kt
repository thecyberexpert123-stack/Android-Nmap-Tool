package com.thecyberexpert123.nmaptool.contract

data class ToolResultDelta(
    val summary: String,
    val newOpenPorts: List<PortFinding> = emptyList(),
    val closedPorts: List<PortFinding> = emptyList(),
)

object ToolResultDeltaAnalyzer {
    fun compare(
        tool: ToolType,
        previous: ToolResultSummary?,
        current: ToolResultSummary,
    ): ToolResultDelta = when (tool) {
        ToolType.NMAP -> compareNmap(previous = previous, current = current)
        ToolType.NPING -> compareGeneric(tool)
        ToolType.NCAT -> compareGeneric(tool)
    }

    private fun compareNmap(
        previous: ToolResultSummary?,
        current: ToolResultSummary,
    ): ToolResultDelta {
        if (previous == null) {
            return ToolResultDelta(summary = "Baseline findings recorded for this Nmap profile.")
        }

        val previousByKey = previous.portFindings.associateBy(::keyOf)
        val currentByKey = current.portFindings.associateBy(::keyOf)

        val newOpenPorts = currentByKey
            .filterKeys { key -> key !in previousByKey }
            .values
            .sortedWith(compareBy({ it.host.orEmpty() }, { it.port }, { it.protocol }))

        val closedPorts = previousByKey
            .filterKeys { key -> key !in currentByKey }
            .values
            .sortedWith(compareBy({ it.host.orEmpty() }, { it.port }, { it.protocol }))

        if (newOpenPorts.isEmpty() && closedPorts.isEmpty()) {
            return ToolResultDelta(summary = "No open-port delta detected since the previous Nmap run.")
        }

        val parts = mutableListOf<String>()
        if (newOpenPorts.isNotEmpty()) {
            parts += pluralize(newOpenPorts.size, "new open port", "new open ports")
        }
        if (closedPorts.isNotEmpty()) {
            parts += pluralize(closedPorts.size, "previously open port no longer present", "previously open ports no longer present")
        }

        return ToolResultDelta(
            summary = parts.joinToString(separator = "; "),
            newOpenPorts = newOpenPorts.take(24),
            closedPorts = closedPorts.take(24),
        )
    }

    private fun compareGeneric(tool: ToolType): ToolResultDelta =
        ToolResultDelta(summary = "No specialized delta analysis for ${tool.binaryName} output yet.")

    private fun keyOf(finding: PortFinding): String =
        buildString {
            append(finding.host.orEmpty())
            append('|')
            append(finding.port)
            append('/')
            append(finding.protocol.lowercase())
        }

    private fun pluralize(count: Int, singular: String, plural: String): String =
        "$count ${if (count == 1) singular else plural}"
}
