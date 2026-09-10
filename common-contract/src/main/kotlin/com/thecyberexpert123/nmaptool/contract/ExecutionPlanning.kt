package com.thecyberexpert123.nmaptool.contract

private val nmapRawAccessFlags = setOf(
    "-sS",
    "-sU",
    "-sA",
    "-sW",
    "-sM",
    "-sN",
    "-sF",
    "-sX",
    "--send-eth",
    "--send-ip",
    "-O",
    "--traceroute",
)

private val npingRawProbeFlags = setOf(
    "--tcp",
    "--udp",
    "--icmp",
    "--arp",
    "--tr",
    "--traceroute",
)

enum class ExecutionGuidanceStatus {
    READY,
    CAUTION,
    BLOCKED,
}

data class ExecutionGuidance(
    val status: ExecutionGuidanceStatus = ExecutionGuidanceStatus.CAUTION,
    val likelyRoute: ExecutionRoute? = null,
    val likelyExecutorTitle: String? = null,
    val summary: String = "Complete the profile and verify capabilities to evaluate execution readiness.",
    val blockers: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
)

object ExecutionGuidanceAdvisor {
    fun analyze(
        tool: ToolType,
        targets: List<String>,
        executionPreference: ExecutionPreference,
        arguments: List<String>,
        remoteConfigured: Boolean,
        remoteCapabilities: RemoteCapabilitiesResponse?,
        remoteCapabilitiesStale: Boolean,
        localCapabilities: AndroidLocalCapabilities,
        scheduleEnabled: Boolean,
    ): ExecutionGuidance {
        val blockers = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        val notes = mutableListOf<String>()
        val currentCapabilities = remoteCapabilities.takeIf { remoteConfigured && !remoteCapabilitiesStale }
        val remoteToolAvailable = currentCapabilities?.isToolAvailable(tool)
        val localAssessment = AndroidLocalExecutionPlanner.assess(
            tool = tool,
            targets = targets,
            arguments = arguments,
            capabilities = localCapabilities,
        )

        when (executionPreference) {
            ExecutionPreference.LOCAL_ONLY -> {
                if (!localAssessment.supported) {
                    blockers += localAssessment.blockers.ifEmpty {
                        listOf("Android-local execution is not currently viable for this profile.")
                    }
                }
            }

            ExecutionPreference.REMOTE_ONLY -> {
                if (!remoteConfigured) {
                    blockers += "REMOTE ONLY was selected, but no delegated executor base URL is configured."
                }
            }

            ExecutionPreference.AUTO -> {
                if (!localAssessment.supported && !remoteConfigured) {
                    blockers += "AUTO currently has no viable route because Android-local execution is not viable and no delegated executor is configured."
                    blockers += localAssessment.blockers
                }
            }
        }

        if (scheduleEnabled) {
            notes += "Scheduled scans still depend on WorkManager timing, notification, and network constraints on Android."
        }

        val likelyRoute = when (executionPreference) {
            ExecutionPreference.LOCAL_ONLY -> if (localAssessment.supported) ExecutionRoute.LOCAL else null
            ExecutionPreference.REMOTE_ONLY -> if (remoteConfigured) ExecutionRoute.REMOTE else null
            ExecutionPreference.AUTO -> when {
                localAssessment.supported -> ExecutionRoute.LOCAL
                remoteConfigured -> ExecutionRoute.REMOTE
                else -> null
            }
        }
        val likelyExecutorTitle = when (likelyRoute) {
            ExecutionRoute.LOCAL -> localCapabilities.toExecutorCapabilityProfile().label
            ExecutionRoute.REMOTE -> remoteCapabilities?.executorProfile?.label
                ?: remoteCapabilities?.executorLabel?.takeIf(String::isNotBlank)
                ?: "Delegated remote Nmap executor"
            ExecutionRoute.BLOCKED, null -> null
        }

        if (likelyRoute == ExecutionRoute.REMOTE) {
            if (remoteCapabilities == null) {
                warnings += "A delegated executor is configured, but its capabilities have not been checked yet. Refresh capabilities before trusting route assumptions."
            } else if (remoteCapabilitiesStale) {
                warnings += "Displayed delegated-executor capabilities are stale relative to the current unsaved settings. Save or refresh before trusting them."
            } else if (remoteToolAvailable == false) {
                blockers += "The delegated executor does not currently report ${tool.binaryName} as available."
            }
        }

        if (executionPreference == ExecutionPreference.AUTO && !localAssessment.supported && remoteConfigured) {
            notes += "AUTO will currently route this profile to the delegated executor because Android-local execution is not viable for this profile."
        }

        if (likelyRoute == ExecutionRoute.LOCAL) {
            warnings += localAssessment.warnings
            notes += localAssessment.notes
        } else if (!localAssessment.supported) {
            notes += localAssessment.blockers.map { blocker -> "Local route limitation: $blocker" }
        }

        currentCapabilities?.let { capabilities ->
            capabilities.executorLabel?.takeIf(String::isNotBlank)?.let { label ->
                notes += "Verified against executor \"$label\"."
            }
            capabilities.versionBannerFor(tool)?.takeIf(String::isNotBlank)?.let { banner ->
                notes += "Detected ${tool.binaryName} version banner: $banner"
            }
            if (tool == ToolType.NMAP) {
                if (capabilities.supportsStructuredNmapXml) {
                    notes += "The delegated executor reports structured Nmap XML support for higher-fidelity saved summaries."
                } else {
                    warnings += "The delegated executor does not report structured Nmap XML support; saved Nmap summaries will rely on text heuristics."
                }
            }
        }

        val privilegedAccessReasons = if (likelyRoute == ExecutionRoute.LOCAL) {
            emptyList()
        } else {
            detectPrivilegedAccessReasons(tool, arguments)
        }
        if (privilegedAccessReasons.isNotEmpty()) {
            val reasonText = privilegedAccessReasons.joinToString(separator = "; ")
            if (currentCapabilities?.privileged == true) {
                notes += "Selected options may depend on privileged/raw access, and the verified executor reports privileged mode: $reasonText"
            } else {
                warnings += "Selected options may depend on privileged/raw access: $reasonText"
            }
        }

        val status = when {
            blockers.isNotEmpty() -> ExecutionGuidanceStatus.BLOCKED
            warnings.isNotEmpty() -> ExecutionGuidanceStatus.CAUTION
            else -> ExecutionGuidanceStatus.READY
        }

        val summary = when {
            status == ExecutionGuidanceStatus.BLOCKED -> "No fully viable execution route is currently available for this profile."
            likelyRoute == ExecutionRoute.REMOTE && status == ExecutionGuidanceStatus.READY -> "This profile is ready to run through the delegated executor."
            likelyRoute == ExecutionRoute.REMOTE -> "This profile is likely to run through the delegated executor, but review the warnings below."
            likelyRoute == ExecutionRoute.LOCAL && status == ExecutionGuidanceStatus.READY -> "This profile is ready to run locally."
            likelyRoute == ExecutionRoute.LOCAL -> "This profile can run locally, but review the warnings below."
            else -> "Execution readiness could not be determined from the current inputs."
        }

        return ExecutionGuidance(
            status = status,
            likelyRoute = likelyRoute,
            likelyExecutorTitle = likelyExecutorTitle,
            summary = summary,
            blockers = blockers.distinct(),
            warnings = warnings.distinct(),
            notes = notes.distinct(),
        )
    }

    private fun detectPrivilegedAccessReasons(tool: ToolType, arguments: List<String>): List<String> = when (tool) {
        ToolType.NMAP -> arguments.filter { argument -> argument in nmapRawAccessFlags }
            .map { flag ->
                when (flag) {
                    "-sS" -> "-sS SYN scan requires raw-packet privileges on typical Unix-like hosts"
                    "-O" -> "-O OS detection is privilege-sensitive and may fail or degrade without raw access"
                    "--traceroute" -> "--traceroute behavior depends on how the executor host can probe the network"
                    else -> "$flag is a lower-level scan/probe mode that may fail or degrade without privileged/raw access"
                }
            }

        ToolType.NPING -> {
            if (arguments.contains("--tcp-connect")) {
                emptyList()
            } else {
                arguments.filter { argument -> argument in npingRawProbeFlags }
                    .map { flag -> "$flag probe mode may require privileged/raw packet access" }
            }
        }

        ToolType.NCAT -> emptyList()
    }

    private fun RemoteCapabilitiesResponse.isToolAvailable(tool: ToolType): Boolean = when (tool) {
        ToolType.NMAP -> nmapAvailable
        ToolType.NCAT -> ncatAvailable
        ToolType.NPING -> npingAvailable
    }

    private fun RemoteCapabilitiesResponse.versionBannerFor(tool: ToolType): String? = when (tool) {
        ToolType.NMAP -> nmapVersion
        ToolType.NCAT -> ncatVersion
        ToolType.NPING -> npingVersion
    }
}
