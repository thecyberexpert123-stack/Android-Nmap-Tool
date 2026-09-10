package com.thecyberexpert123.nmaptool.contract

import kotlinx.serialization.Serializable

@Serializable
enum class ToolType {
    NMAP,
    NCAT,
    NPING;

    val binaryName: String
        get() = name.lowercase()
}

@Serializable
enum class ExecutionPreference {
    AUTO,
    LOCAL_ONLY,
    REMOTE_ONLY,
}

@Serializable
enum class ExecutionRoute {
    LOCAL,
    REMOTE,
    BLOCKED,
}

@Serializable
enum class RunStatus {
    SUCCEEDED,
    FAILED,
    BLOCKED,
}

@Serializable
enum class RunTrigger {
    MANUAL,
    SCHEDULED,
}

@Serializable
data class ToolInvocationRequest(
    val profileName: String,
    val tool: ToolType,
    val executionPreference: ExecutionPreference,
    val targets: List<String>,
    val arguments: List<String>,
    val notes: String = "",
    val requestedAtEpochMillis: Long,
    val requestedBy: RunTrigger,
)

@Serializable
data class ToolInvocationResponse(
    val route: ExecutionRoute,
    val status: RunStatus,
    val commandPreview: String,
    val exitCode: Int? = null,
    val stdout: String = "",
    val stderr: String = "",
    val startedAtEpochMillis: Long,
    val finishedAtEpochMillis: Long,
    val message: String = "",
    val nmapXmlOutput: String? = null,
)

@Serializable
data class RemoteCapabilitiesResponse(
    val nmapAvailable: Boolean,
    val ncatAvailable: Boolean,
    val npingAvailable: Boolean,
    val privileged: Boolean,
    val requiresAuthentication: Boolean,
    val maxTargetsPerRequest: Int,
    val maxArgumentsPerRequest: Int,
    val outputCaptureLimitBytes: Int,
    val targetPolicySummary: String,
    val advisory: String,
    val supportsStructuredNmapXml: Boolean = false,
)

@Serializable
data class ApiErrorResponse(
    val message: String,
)

data class ValidationIssue(
    val field: String,
    val message: String,
)

data class ValidationResult<T>(
    val value: T? = null,
    val issues: List<ValidationIssue> = emptyList(),
) {
    val isValid: Boolean
        get() = value != null && issues.isEmpty()

    companion object {
        fun <T> success(value: T): ValidationResult<T> = ValidationResult(value = value)

        fun <T> failure(vararg issues: ValidationIssue): ValidationResult<T> =
            ValidationResult(value = null, issues = issues.toList())

        fun <T> failure(issues: List<ValidationIssue>): ValidationResult<T> =
            ValidationResult(value = null, issues = issues)
    }
}

data class ValidatedToolInvocation(
    val request: ToolInvocationRequest,
) {
    val commandPreview: String
        get() = CommandPreview.render(
            tool = request.tool,
            arguments = request.arguments,
            targets = request.targets,
        )
}

enum class ScanPreset(
    val displayName: String,
    val tool: ToolType,
    val suggestedArguments: List<String>,
    val description: String,
) {
    QUICK_TCP(
        displayName = "Quick TCP",
        tool = ToolType.NMAP,
        suggestedArguments = listOf("-Pn", "-T4", "-F"),
        description = "Fast connect-oriented scan profile for broad compatibility.",
    ),
    SERVICE_DISCOVERY(
        displayName = "Service Discovery",
        tool = ToolType.NMAP,
        suggestedArguments = listOf("-Pn", "-sV", "-T4"),
        description = "Detect likely services and versions.",
    ),
    AGGRESSIVE_PROFILE(
        displayName = "Aggressive Profile",
        tool = ToolType.NMAP,
        suggestedArguments = listOf("-A", "-Pn"),
        description = "Runs OS/service/script/traceroute features where the executor allows them.",
    ),
    TCP_BANNER_WITH_NCAT(
        displayName = "Banner Grab (Ncat)",
        tool = ToolType.NCAT,
        suggestedArguments = listOf("-v"),
        description = "Interactive or banner-oriented TCP connection helper.",
    ),
    HOST_LATENCY_WITH_NPING(
        displayName = "Latency Probe (Nping)",
        tool = ToolType.NPING,
        suggestedArguments = listOf("--tcp"),
        description = "Probe reachability and latency with nping.",
    ),
}

object CommandPreview {
    fun render(tool: ToolType, arguments: List<String>, targets: List<String>): String {
        val parts = buildList {
            add(tool.binaryName)
            addAll(arguments)
            addAll(targets)
        }
        return renderTokens(parts)
    }

    fun renderArguments(arguments: List<String>): String = renderTokens(arguments)

    private fun renderTokens(tokens: List<String>): String =
        tokens.joinToString(separator = " ") { token ->
            if (token.any(Char::isWhitespace)) {
                buildString {
                    append('"')
                    append(token.replace("\"", "\\\""))
                    append('"')
                }
            } else {
                token
            }
        }
}
