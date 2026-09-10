package com.thecyberexpert123.nmaptool.contract

import kotlinx.serialization.Serializable

@Serializable
enum class ExecutorNodeKind {
    ANDROID_LOCAL,
    REMOTE_NMAP,
    LAN_AGENT,
    UNKNOWN,
}

@Serializable
enum class ExecutorTransportKind {
    ON_DEVICE,
    HTTPS,
    VPN_TUNNEL,
    PRIVATE_OVERLAY,
    UNKNOWN,
}

@Serializable
enum class ExecutionCapabilityId {
    TCP_CONNECT_SCAN,
    UDP_APPLICATION_PROBES,
    PASSIVE_BANNER_CAPTURE,
    CURATED_SERVICE_DETECTION,
    ANDROID_FINGERPRINT_INFERENCE,
    RAW_PACKET_PROBES,
    NMAP_OS_DETECTION,
    NSE_SCRIPTS,
    TRACEROUTE,
    STRUCTURED_NMAP_XML,
    AUTHENTICATED_API,
    AUDIT_LOGGING,
    CONCURRENCY_GOVERNANCE,
}

@Serializable
enum class ExecutionCapabilityLevel {
    SUPPORTED,
    LIMITED,
    UNSUPPORTED,
}

@Serializable
data class ExecutionCapabilityDescriptor(
    val id: ExecutionCapabilityId,
    val level: ExecutionCapabilityLevel,
    val summary: String,
)

@Serializable
data class ExecutorCapabilityProfile(
    val id: String,
    val label: String,
    val kind: ExecutorNodeKind,
    val transport: ExecutorTransportKind,
    val available: Boolean,
    val requiresAuthentication: Boolean,
    val privileged: Boolean,
    val advisory: String,
    val capabilities: List<ExecutionCapabilityDescriptor> = emptyList(),
    val maxTargetsPerRun: Int? = null,
    val maxArgumentsPerRun: Int? = null,
    val maxPortsPerTarget: Int? = null,
    val maxTotalProbesPerRun: Int? = null,
    val maxConcurrentExecutions: Int? = null,
    val outputCaptureLimitBytes: Int? = null,
    val activeNetworkSummary: String? = null,
)

fun AndroidLocalCapabilities.toExecutorCapabilityProfile(
    label: String = "Android local executor",
): ExecutorCapabilityProfile = ExecutorCapabilityProfile(
    id = "android-local",
    label = label,
    kind = ExecutorNodeKind.ANDROID_LOCAL,
    transport = ExecutorTransportKind.ON_DEVICE,
    available = available,
    requiresAuthentication = false,
    privileged = false,
    advisory = advisory,
    capabilities = listOf(
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.TCP_CONNECT_SCAN,
            level = if (supportsTcpConnectScan && networkAvailable) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = if (supportsTcpConnectScan) {
                "Bounded TCP connect scanning is available through ordinary Android socket APIs."
            } else {
                "TCP connect scanning is not available in this Android runtime."
            },
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.UDP_APPLICATION_PROBES,
            level = if (supportsUdpDatagramProbes && networkAvailable) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = if (supportsUdpDatagramProbes) {
                "UDP datagram probes are available, but silent/no-response outcomes remain conservative and inconclusive."
            } else {
                "UDP datagram probes are not available in this Android runtime."
            },
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.PASSIVE_BANNER_CAPTURE,
            level = if (networkAvailable) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = "Single-session TCP banner capture is available for bounded local Ncat-style probing.",
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.CURATED_SERVICE_DETECTION,
            level = if (supportsServiceDetection && networkAvailable) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = if (supportsServiceDetection) {
                "Curated Android-local service detection is enabled for selected protocols and bounded to $maxServiceDetectionsPerRun open TCP endpoints per run."
            } else {
                "Curated Android-local service detection is not implemented in this phase yet."
            },
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.ANDROID_FINGERPRINT_INFERENCE,
            level = if (supportsAndroidFingerprinting && networkAvailable) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = if (supportsAndroidFingerprinting) {
                "Evidence-based Android-local fingerprint inference is enabled for selected OS-family and device-type hints; it is not raw TCP/IP stack fingerprinting parity."
            } else {
                "Android-local fingerprint inference is not implemented yet."
            },
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.RAW_PACKET_PROBES,
            level = ExecutionCapabilityLevel.UNSUPPORTED,
            summary = "Stock Android app execution does not provide arbitrary raw packet transmission or capture.",
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.NMAP_OS_DETECTION,
            level = if (supportsNmapOsDetection) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = if (supportsNmapOsDetection) {
                "Nmap-style OS detection parity is only partially available."
            } else {
                "Nmap -O parity is not available in Android-local mode."
            },
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.NSE_SCRIPTS,
            level = if (supportsNmapDefaultScripts) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = if (supportsNmapDefaultScripts) {
                "Some script-driven behavior is available locally."
            } else {
                "NSE/default-script parity is not available in Android-local mode."
            },
        ),
        ExecutionCapabilityDescriptor(
            id = ExecutionCapabilityId.TRACEROUTE,
            level = if (supportsTraceroute) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
            summary = if (supportsTraceroute) {
                "Traceroute is partially available in Android-local mode."
            } else {
                "Traceroute is not available in Android-local mode."
            },
        ),
    ),
    maxTargetsPerRun = maxTargetsPerRun,
    maxPortsPerTarget = maxPortsPerTarget,
    maxTotalProbesPerRun = maxTotalProbes,
    maxConcurrentExecutions = null,
    outputCaptureLimitBytes = null,
    activeNetworkSummary = activeNetworkSummary,
)

fun RemoteCapabilitiesResponse.toExecutorCapabilityProfile(
    labelOverride: String? = null,
): ExecutorCapabilityProfile {
    val label = labelOverride?.takeIf(String::isNotBlank)
        ?: executorLabel?.takeIf(String::isNotBlank)
        ?: "Delegated Nmap executor"
    return ExecutorCapabilityProfile(
        id = executorLabel?.takeIf(String::isNotBlank)?.lowercase()?.replace(Regex("[^a-z0-9-]+"), "-")
            ?: "remote-nmap-executor",
        label = label,
        kind = ExecutorNodeKind.REMOTE_NMAP,
        transport = ExecutorTransportKind.HTTPS,
        available = nmapAvailable || ncatAvailable || npingAvailable,
        requiresAuthentication = requiresAuthentication,
        privileged = privileged,
        advisory = advisory,
        capabilities = listOf(
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.TCP_CONNECT_SCAN,
                level = if (nmapAvailable || ncatAvailable || npingAvailable) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = "Delegated execution can perform ordinary socket-based probing on the remote host when the selected tool is available.",
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.UDP_APPLICATION_PROBES,
                level = if (nmapAvailable || npingAvailable) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = "Remote execution can perform broader UDP probing than stock Android-local mode when the remote host is correctly configured.",
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.PASSIVE_BANNER_CAPTURE,
                level = if (ncatAvailable) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = if (ncatAvailable) {
                    "Ncat is available for delegated TCP session and banner-oriented probing."
                } else {
                    "Ncat is not currently available on this delegated executor."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.CURATED_SERVICE_DETECTION,
                level = if (nmapAvailable) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = if (nmapAvailable) {
                    "Nmap-backed service detection can run remotely when allowed by host privileges and policy."
                } else {
                    "Nmap is not currently available on this delegated executor."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.ANDROID_FINGERPRINT_INFERENCE,
                level = ExecutionCapabilityLevel.UNSUPPORTED,
                summary = "Android-local fingerprint inference does not apply to this delegated executor profile.",
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.RAW_PACKET_PROBES,
                level = if (privileged) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.LIMITED,
                summary = if (privileged) {
                    "The remote host reports privileged mode, so raw-packet-dependent scans are more likely to be available."
                } else {
                    "The remote host does not report privileged mode, so raw-packet-dependent scans may fail or degrade."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.NMAP_OS_DETECTION,
                level = if (nmapAvailable && privileged) ExecutionCapabilityLevel.SUPPORTED else if (nmapAvailable) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = when {
                    !nmapAvailable -> "Nmap is not currently available on this delegated executor."
                    privileged -> "Remote Nmap OS detection is supported when the target path and host privileges allow it."
                    else -> "Remote Nmap OS detection is tool-available but privilege-sensitive on this host."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.NSE_SCRIPTS,
                level = if (nmapAvailable) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = if (nmapAvailable) {
                    "Remote Nmap supports script-capable execution subject to the executor's safety policy."
                } else {
                    "Nmap is not currently available on this delegated executor."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.TRACEROUTE,
                level = if (nmapAvailable) ExecutionCapabilityLevel.LIMITED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = if (nmapAvailable) {
                    "Traceroute can be delegated remotely, but results still depend on topology and host/network privileges."
                } else {
                    "Nmap is not currently available on this delegated executor."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.STRUCTURED_NMAP_XML,
                level = if (supportsStructuredNmapXml) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.UNSUPPORTED,
                summary = if (supportsStructuredNmapXml) {
                    "Structured Nmap XML capture is available for higher-fidelity result parsing."
                } else {
                    "Structured Nmap XML capture is not available from this delegated executor."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.AUTHENTICATED_API,
                level = if (requiresAuthentication) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.LIMITED,
                summary = if (requiresAuthentication) {
                    "This executor requires authenticated API access."
                } else {
                    "This executor currently accepts unauthenticated API access; use only on intentionally trusted deployments."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.AUDIT_LOGGING,
                level = if (auditLoggingEnabled) ExecutionCapabilityLevel.SUPPORTED else ExecutionCapabilityLevel.LIMITED,
                summary = if (auditLoggingEnabled) {
                    "Request-correlated audit logging is enabled on this executor."
                } else {
                    "Audit logging is not enabled on this executor."
                },
            ),
            ExecutionCapabilityDescriptor(
                id = ExecutionCapabilityId.CONCURRENCY_GOVERNANCE,
                level = ExecutionCapabilityLevel.SUPPORTED,
                summary = "Executor-side concurrency governance is configured with a limit of $maxConcurrentExecutions simultaneous executions.",
            ),
        ),
        maxTargetsPerRun = maxTargetsPerRequest,
        maxArgumentsPerRun = maxArgumentsPerRequest,
        maxPortsPerTarget = null,
        maxTotalProbesPerRun = null,
        maxConcurrentExecutions = maxConcurrentExecutions,
        outputCaptureLimitBytes = outputCaptureLimitBytes,
        activeNetworkSummary = null,
    )
}
