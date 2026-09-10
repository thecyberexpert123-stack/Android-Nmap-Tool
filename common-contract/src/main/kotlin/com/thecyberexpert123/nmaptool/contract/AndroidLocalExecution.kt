package com.thecyberexpert123.nmaptool.contract

private val androidLocalTimingTemplatePattern = Regex("^-T[0-5]$")
private val androidLocalNmapRawFlags = setOf(
    "-sS",
    "-sU",
    "-sA",
    "-sW",
    "-sM",
    "-sN",
    "-sF",
    "-sX",
    "-sY",
    "-sZ",
    "-sO",
    "-sI",
    "--send-eth",
    "--send-ip",
)
private val androidLocalNpingRawFlags = setOf(
    "--tcp",
    "--icmp",
    "--arp",
    "--tr",
    "--traceroute",
)
private val curatedTcpPortCatalog = listOf(
    7, 9, 13, 21, 22, 23, 25, 37, 53, 79,
    80, 81, 82, 83, 84, 85, 88, 110, 111, 113,
    119, 123, 135, 139, 143, 179, 199, 389, 427, 443,
    444, 445, 465, 497, 500, 512, 513, 514, 515, 548,
    554, 587, 631, 636, 646, 873, 902, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1080, 1099, 1110, 1194, 1433,
    1434, 1521, 1720, 1723, 1755, 1812, 1813, 1900, 2000, 2049,
    2121, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3268, 3306,
    3389, 3478, 3690, 4333, 4443, 4500, 5000, 5060, 5061, 5353,
    5432, 5500, 5601, 5672, 5900, 5984, 6000, 6379, 6443, 6667,
    7001, 7002, 7070, 8000, 8008, 8080, 8081, 8088, 8090, 8091,
    8200, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300,
    9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017,
)

private const val defaultLocalAdvisory =
    "Android-local execution uses permitted socket APIs for TCP connect scans, curated service identification, and limited TCP/UDP probes. It does not provide raw packets, NSE parity, traceroute, or Nmap -O parity on stock Android."

data class AndroidLocalCapabilities(
    val available: Boolean = true,
    val networkAvailable: Boolean = true,
    val activeNetworkSummary: String? = null,
    val supportsTcpConnectScan: Boolean = true,
    val supportsUdpDatagramProbes: Boolean = true,
    val supportsServiceDetection: Boolean = false,
    val supportsAndroidFingerprinting: Boolean = false,
    val supportsRawPackets: Boolean = false,
    val supportsNmapOsDetection: Boolean = false,
    val supportsNmapDefaultScripts: Boolean = false,
    val supportsTraceroute: Boolean = false,
    val fastModePortCatalogSize: Int = 100,
    val maxPortsPerTarget: Int = 256,
    val maxTargetsPerRun: Int = 16,
    val maxTotalProbes: Int = 1024,
    val maxServiceDetectionsPerRun: Int = 32,
    val advisory: String = defaultLocalAdvisory,
)

data class AndroidLocalExecutionAssessment(
    val supported: Boolean,
    val summary: String,
    val preferDelegatedWhenAvailable: Boolean = false,
    val blockers: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
)

data class AndroidLocalNmapPlan(
    val ports: List<Int>,
    val skipHostDiscovery: Boolean,
    val enableServiceDetection: Boolean,
    val connectTimeoutMillis: Int,
    val serviceReadTimeoutMillis: Int,
    val maxConcurrency: Int,
    val usedCuratedPortCatalog: Boolean,
    val topPortsRequested: Int? = null,
)

data class AndroidLocalNcatPlan(
    val host: String,
    val port: Int,
    val connectTimeoutMillis: Int,
    val readTimeoutMillis: Int,
    val verbose: Boolean,
    val zeroIo: Boolean,
)

enum class AndroidLocalNpingMode {
    TCP_CONNECT,
    UDP,
}

data class AndroidLocalNpingPlan(
    val host: String,
    val port: Int,
    val mode: AndroidLocalNpingMode,
    val count: Int,
    val delayMillis: Long,
    val connectTimeoutMillis: Int,
    val responseTimeoutMillis: Int,
)

object AndroidLocalExecutionPlanner {
    fun assess(
        tool: ToolType,
        targets: List<String>,
        arguments: List<String>,
        capabilities: AndroidLocalCapabilities,
    ): AndroidLocalExecutionAssessment {
        val blockers = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        val notes = mutableListOf<String>()

        if (!capabilities.available) {
            blockers += "Android-local execution is not available in this runtime."
        }
        if (!capabilities.networkAvailable) {
            blockers += "No active Android network is currently available for local probing."
        }
        capabilities.activeNetworkSummary?.takeIf(String::isNotBlank)?.let { summary ->
            notes += "Active network snapshot: $summary"
        }
        if (targets.isEmpty()) {
            blockers += "At least one target is required for Android-local execution."
        }
        if (targets.size > capabilities.maxTargetsPerRun) {
            blockers += "Android-local mode currently supports at most ${capabilities.maxTargetsPerRun} targets per run."
        }

        targets.forEachIndexed { index, target ->
            val endpoint = parseTargetEndpoint(target)
            val normalizedTarget = endpoint.host
            if (normalizedTarget.contains('/')) {
                blockers += "targets[$index]: Android-local mode currently supports discrete hosts only, not CIDR/range targets: $target"
            }
            if (tool == ToolType.NMAP && endpoint.port != null) {
                blockers += "targets[$index]: Android-local Nmap mode expects host targets only; specify TCP ports through -p, --top-ports, or -F instead of embedding a port in the target."
            }
        }

        var preferDelegatedWhenAvailable = false

        when (tool) {
            ToolType.NMAP -> {
                val planResult = createNmapPlan(arguments, capabilities)
                blockers += planResult.issues.map { it.message }
                planResult.value?.let { plan ->
                    if (plan.ports.size > capabilities.maxPortsPerTarget) {
                        blockers += "Android-local TCP connect scans are limited to ${capabilities.maxPortsPerTarget} ports per target in this baseline."
                    }
                    val totalProbes = plan.ports.size * targets.size
                    if (totalProbes > capabilities.maxTotalProbes) {
                        blockers += "Android-local mode limits each run to ${capabilities.maxTotalProbes} total socket probes; reduce targets or ports, or use a delegated executor."
                    }
                    if (!plan.skipHostDiscovery) {
                        warnings += "Without -Pn, Android-local mode still relies on connect-based reachability inference instead of raw ICMP/ARP host discovery."
                    }
                    if (plan.usedCuratedPortCatalog) {
                        warnings += if (plan.topPortsRequested != null) {
                            "Android-local --top-ports uses the app's curated TCP port catalog, not Nmap's exact service-frequency database."
                        } else {
                            "Android-local -F uses the app's curated fast TCP port catalog, not Nmap's exact service-frequency database."
                        }
                    }
                    if (plan.enableServiceDetection) {
                        warnings += "Android-local -sV uses curated protocol detection for selected services and is not full Nmap version-detection parity."
                        notes += "Android-local curated service identification will probe up to ${capabilities.maxServiceDetectionsPerRun} open TCP endpoints per run."
                        preferDelegatedWhenAvailable = true
                    }
                    notes += if (plan.enableServiceDetection) {
                        "Android-local Nmap mode supports TCP connect scanning with limited curated service detection in this phase-B baseline."
                    } else {
                        "Android-local Nmap mode supports bounded TCP connect scanning in this phase-B baseline."
                    }
                }
            }

            ToolType.NCAT -> {
                val planResult = createNcatPlan(targets, arguments)
                blockers += planResult.issues.map { it.message }
                if (planResult.value != null) {
                    notes += "Android-local Ncat mode opens one TCP session and performs passive banner capture only."
                }
            }

            ToolType.NPING -> {
                val planResult = createNpingPlan(targets, arguments, capabilities)
                blockers += planResult.issues.map { it.message }
                planResult.value?.let { plan ->
                    if (plan.mode == AndroidLocalNpingMode.UDP) {
                        warnings += "UDP no-response results remain inconclusive on stock Android because app-visible socket APIs do not provide full raw ICMP visibility."
                    }
                    notes += when (plan.mode) {
                        AndroidLocalNpingMode.TCP_CONNECT -> "Android-local Nping mode measures connect-based TCP latency rather than raw packet RTT."
                        AndroidLocalNpingMode.UDP -> "Android-local Nping UDP mode measures datagram-response timing only when the target application replies."
                    }
                }
            }
        }

        val supported = blockers.isEmpty()
        val summary = when {
            supported && tool == ToolType.NMAP && preferDelegatedWhenAvailable -> "Android-local TCP connect scanning with curated service identification is available for this profile."
            supported && tool == ToolType.NMAP -> "Android-local TCP connect scanning is available for this profile."
            supported && tool == ToolType.NCAT -> "Android-local TCP session probing is available for this profile."
            supported && tool == ToolType.NPING -> "Android-local latency probing is available for this profile."
            blockers.isNotEmpty() -> blockers.first()
            else -> "Android-local execution readiness could not be determined."
        }

        return AndroidLocalExecutionAssessment(
            supported = supported,
            summary = summary,
            preferDelegatedWhenAvailable = preferDelegatedWhenAvailable,
            blockers = blockers.distinct(),
            warnings = warnings.distinct(),
            notes = notes.distinct(),
        )
    }

    fun createNmapPlan(
        arguments: List<String>,
        capabilities: AndroidLocalCapabilities,
    ): ValidationResult<AndroidLocalNmapPlan> {
        val issues = mutableListOf<ValidationIssue>()
        var skipHostDiscovery = false
        var enableServiceDetection = false
        var useFastCatalog = false
        var explicitPortSpec: String? = null
        var topPorts: Int? = null
        var timingToken: String? = null

        var index = 0
        while (index < arguments.size) {
            val argument = arguments[index]
            when {
                argument == "-Pn" -> skipHostDiscovery = true
                argument == "-sT" -> Unit
                argument == "-sV" -> {
                    if (capabilities.supportsServiceDetection) {
                        enableServiceDetection = true
                    } else {
                        issues += ValidationIssue(
                            "arguments[$index]",
                            "Android-local service detection is not available in this runtime, so -sV requires a delegated executor.",
                        )
                    }
                }
                argument == "-n" -> Unit
                argument == "--unprivileged" -> Unit
                argument == "-F" -> useFastCatalog = true
                androidLocalTimingTemplatePattern.matches(argument) -> timingToken = argument
                argument == "-p" -> {
                    val value = arguments.getOrNull(index + 1)
                    if (value == null) {
                        issues += ValidationIssue("arguments[$index]", "-p requires a port list value for Android-local Nmap mode.")
                    } else {
                        explicitPortSpec = value
                        index += 1
                    }
                }

                argument.startsWith("-p") && argument.length > 2 -> explicitPortSpec = argument.drop(2)
                argument == "--top-ports" -> {
                    val value = arguments.getOrNull(index + 1)
                    if (value == null) {
                        issues += ValidationIssue("arguments[$index]", "--top-ports requires a numeric value for Android-local Nmap mode.")
                    } else {
                        topPorts = value.toIntOrNull()
                        if (topPorts == null) {
                            issues += ValidationIssue("arguments[$index]", "--top-ports must be a whole number in Android-local Nmap mode.")
                        }
                        index += 1
                    }
                }

                argument.startsWith("--top-ports=") -> {
                    topPorts = argument.substringAfter('=').toIntOrNull()
                    if (topPorts == null) {
                        issues += ValidationIssue("arguments[$index]", "--top-ports must be a whole number in Android-local Nmap mode.")
                    }
                }

                argument == "-sC" -> issues += ValidationIssue("arguments[$index]", "Android-local phase-B Nmap mode does not support -sC default scripts. Use a delegated executor for NSE/script execution.")
                argument == "-O" -> issues += ValidationIssue("arguments[$index]", "Android-local phase-B Nmap mode does not support -O OS detection parity. Use a delegated executor for real Nmap OS fingerprinting.")
                argument == "--traceroute" -> issues += ValidationIssue("arguments[$index]", "Android-local phase-B Nmap mode does not support traceroute. Use a delegated executor when traceroute is required.")
                argument == "--script" || argument.startsWith("--script=") -> issues += ValidationIssue("arguments[$index]", "Android-local phase-B Nmap mode does not support NSE script selection. Use a delegated executor for script-backed scans.")
                argument in androidLocalNmapRawFlags -> issues += ValidationIssue("arguments[$index]", "$argument requires lower-level/raw packet behavior that stock Android app execution does not provide.")
                argument.startsWith("-") -> issues += ValidationIssue("arguments[$index]", "Android-local phase-B Nmap mode does not support option $argument.")
                else -> issues += ValidationIssue("arguments[$index]", "Unexpected positional token in Android-local Nmap arguments: $argument")
            }
            index += 1
        }

        if (listOfNotNull(explicitPortSpec, topPorts, useFastCatalog.takeIf { it }).size > 1) {
            issues += ValidationIssue("arguments", "Choose only one Android-local port strategy: -p, --top-ports, or -F.")
        }

        val ports = when {
            explicitPortSpec != null -> parseTcpPortSpec(explicitPortSpec).also { issues += it.issues }.value
            topPorts != null -> {
                val requested = topPorts!!
                when {
                    requested < 1 -> {
                        issues += ValidationIssue("arguments", "--top-ports must be at least 1 for Android-local Nmap mode.")
                        null
                    }

                    requested > curatedTcpPortCatalog.size -> {
                        issues += ValidationIssue(
                            "arguments",
                            "Android-local phase-B Nmap mode supports at most ${curatedTcpPortCatalog.size} curated top ports.",
                        )
                        null
                    }

                    else -> curatedTcpPortCatalog.take(requested)
                }
            }

            useFastCatalog -> curatedTcpPortCatalog.take(capabilities.fastModePortCatalogSize.coerceAtMost(curatedTcpPortCatalog.size))
            else -> {
                issues += ValidationIssue(
                    "arguments",
                    "Android-local phase-B Nmap mode requires an explicit TCP port strategy such as -p, --top-ports, or -F.",
                )
                null
            }
        }

        if (issues.isNotEmpty() || ports == null) {
            return ValidationResult.failure(issues)
        }

        val timingPolicy = resolveTimingPolicy(timingToken)
        return ValidationResult.success(
            AndroidLocalNmapPlan(
                ports = ports,
                skipHostDiscovery = skipHostDiscovery,
                enableServiceDetection = enableServiceDetection,
                connectTimeoutMillis = timingPolicy.connectTimeoutMillis,
                serviceReadTimeoutMillis = timingPolicy.responseTimeoutMillis,
                maxConcurrency = timingPolicy.maxConcurrency,
                usedCuratedPortCatalog = useFastCatalog || topPorts != null,
                topPortsRequested = topPorts,
            ),
        )
    }

    fun createNcatPlan(
        targets: List<String>,
        arguments: List<String>,
    ): ValidationResult<AndroidLocalNcatPlan> {
        val issues = mutableListOf<ValidationIssue>()
        if (targets.size != 1) {
            issues += ValidationIssue("targets", "Android-local Ncat mode currently supports exactly one target.")
        }
        val endpoint = targets.firstOrNull()?.let(::parseTargetEndpoint)
        var verbose = false
        var zeroIo = false
        var waitSeconds = 3

        var index = 0
        while (index < arguments.size) {
            val argument = arguments[index]
            when (argument) {
                "-v", "-vv" -> verbose = true
                "-z" -> zeroIo = true
                "-w", "--wait" -> {
                    val value = arguments.getOrNull(index + 1)
                    val parsed = value?.toIntOrNull()
                    if (parsed == null || parsed !in 1..60) {
                        issues += ValidationIssue("arguments[$index]", "Android-local Ncat wait time must be a whole number of seconds between 1 and 60.")
                    } else {
                        waitSeconds = parsed
                        index += 1
                    }
                }

                else -> issues += ValidationIssue("arguments[$index]", "Android-local Ncat mode does not support option $argument.")
            }
            index += 1
        }

        val host = endpoint?.host.orEmpty()
        val port = endpoint?.port
        if (host.isBlank()) {
            issues += ValidationIssue("targets", "A host target is required for Android-local Ncat mode.")
        }
        if (port == null) {
            issues += ValidationIssue(
                "targets",
                "Android-local Ncat mode currently requires the target to include a TCP port, for example host:443 or [2001:db8::1]:443.",
            )
        }

        if (issues.isNotEmpty()) {
            return ValidationResult.failure(issues)
        }

        val timeoutMillis = waitSeconds * 1_000
        return ValidationResult.success(
            AndroidLocalNcatPlan(
                host = host,
                port = port!!,
                connectTimeoutMillis = timeoutMillis,
                readTimeoutMillis = timeoutMillis,
                verbose = verbose,
                zeroIo = zeroIo,
            ),
        )
    }

    fun createNpingPlan(
        targets: List<String>,
        arguments: List<String>,
        capabilities: AndroidLocalCapabilities,
    ): ValidationResult<AndroidLocalNpingPlan> {
        val issues = mutableListOf<ValidationIssue>()
        if (targets.size != 1) {
            issues += ValidationIssue("targets", "Android-local Nping mode currently supports exactly one target.")
        }
        val endpoint = targets.firstOrNull()?.let(::parseTargetEndpoint)
        var mode: AndroidLocalNpingMode? = null
        var explicitPort: Int? = null
        var count = 4
        var delayMillis = 250L
        var timingToken: String? = null

        var index = 0
        while (index < arguments.size) {
            val argument = arguments[index]
            when {
                argument == "--tcp-connect" -> mode = AndroidLocalNpingMode.TCP_CONNECT
                argument == "--udp" -> mode = AndroidLocalNpingMode.UDP
                argument in androidLocalNpingRawFlags -> issues += ValidationIssue("arguments[$index]", "$argument requires raw packet access and is not available in Android-local Nping mode.")
                androidLocalTimingTemplatePattern.matches(argument) -> timingToken = argument
                argument == "-p" || argument == "--dest-port" -> {
                    val value = arguments.getOrNull(index + 1)
                    val parsed = value?.toIntOrNull()
                    if (parsed == null || parsed !in 1..65535) {
                        issues += ValidationIssue("arguments[$index]", "Android-local Nping destination port must be between 1 and 65535.")
                    } else {
                        explicitPort = parsed
                        index += 1
                    }
                }

                argument.startsWith("--dest-port=") -> {
                    val parsed = argument.substringAfter('=').toIntOrNull()
                    if (parsed == null || parsed !in 1..65535) {
                        issues += ValidationIssue("arguments[$index]", "Android-local Nping destination port must be between 1 and 65535.")
                    } else {
                        explicitPort = parsed
                    }
                }

                argument == "-c" || argument == "--count" -> {
                    val value = arguments.getOrNull(index + 1)
                    val parsed = value?.toIntOrNull()
                    if (parsed == null || parsed !in 1..10) {
                        issues += ValidationIssue("arguments[$index]", "Android-local Nping count must be a whole number between 1 and 10.")
                    } else {
                        count = parsed
                        index += 1
                    }
                }

                argument.startsWith("--count=") -> {
                    val parsed = argument.substringAfter('=').toIntOrNull()
                    if (parsed == null || parsed !in 1..10) {
                        issues += ValidationIssue("arguments[$index]", "Android-local Nping count must be a whole number between 1 and 10.")
                    } else {
                        count = parsed
                    }
                }

                argument == "--delay" -> {
                    val value = arguments.getOrNull(index + 1)
                    val parsed = value?.let(::parseDelayMillis)
                    if (parsed == null || parsed !in 0L..5_000L) {
                        issues += ValidationIssue("arguments[$index]", "Android-local Nping delay must be between 0 and 5000 milliseconds, optionally using ms or s suffixes.")
                    } else {
                        delayMillis = parsed
                        index += 1
                    }
                }

                argument.startsWith("--delay=") -> {
                    val parsed = parseDelayMillis(argument.substringAfter('='))
                    if (parsed == null || parsed !in 0L..5_000L) {
                        issues += ValidationIssue("arguments[$index]", "Android-local Nping delay must be between 0 and 5000 milliseconds, optionally using ms or s suffixes.")
                    } else {
                        delayMillis = parsed
                    }
                }

                argument == "-v" || argument == "-vv" -> Unit
                argument.startsWith("-") -> issues += ValidationIssue("arguments[$index]", "Android-local Nping mode does not support option $argument.")
                else -> issues += ValidationIssue("arguments[$index]", "Unexpected positional token in Android-local Nping arguments: $argument")
            }
            index += 1
        }

        val host = endpoint?.host.orEmpty()
        val targetPort = endpoint?.port
        if (host.isBlank()) {
            issues += ValidationIssue("targets", "A host target is required for Android-local Nping mode.")
        }
        val port = explicitPort ?: targetPort
        if (port == null) {
            issues += ValidationIssue(
                "targets",
                "Android-local Nping mode currently requires a destination port via -p/--dest-port or host:port target syntax.",
            )
        }
        if (mode == null) {
            issues += ValidationIssue(
                "arguments",
                "Android-local Nping mode requires an explicit supported probe mode: --tcp-connect or --udp.",
            )
        }
        if (mode == AndroidLocalNpingMode.UDP && !capabilities.supportsUdpDatagramProbes) {
            issues += ValidationIssue(
                "arguments",
                "This Android runtime does not currently support UDP application probes for Android-local Nping mode.",
            )
        }

        if (issues.isNotEmpty()) {
            return ValidationResult.failure(issues)
        }

        val timingPolicy = resolveTimingPolicy(timingToken)
        return ValidationResult.success(
            AndroidLocalNpingPlan(
                host = host,
                port = port!!,
                mode = mode!!,
                count = count,
                delayMillis = delayMillis,
                connectTimeoutMillis = timingPolicy.connectTimeoutMillis,
                responseTimeoutMillis = timingPolicy.responseTimeoutMillis,
            ),
        )
    }

    fun curatedTcpPorts(count: Int): List<Int> =
        curatedTcpPortCatalog.take(count.coerceAtMost(curatedTcpPortCatalog.size).coerceAtLeast(0))

    private fun parseTcpPortSpec(rawSpec: String): ValidationResult<List<Int>> {
        val issues = mutableListOf<ValidationIssue>()
        val ports = linkedSetOf<Int>()
        rawSpec.split(',').map(String::trim).filter(String::isNotEmpty).forEachIndexed { index, token ->
            when {
                token.contains(':') -> issues += ValidationIssue(
                    field = "arguments[$index]",
                    message = "Android-local phase-B Nmap mode supports TCP port numbers and ranges only, not protocol-qualified port specs: $token",
                )

                '-' in token -> {
                    val parts = token.split('-', limit = 2)
                    val start = parts.getOrNull(0)?.toIntOrNull()
                    val end = parts.getOrNull(1)?.toIntOrNull()
                    if (start == null || end == null || start !in 1..65535 || end !in 1..65535 || start > end) {
                        issues += ValidationIssue(
                            field = "arguments[$index]",
                            message = "Invalid TCP port range for Android-local phase-B Nmap mode: $token",
                        )
                    } else {
                        (start..end).forEach(ports::add)
                    }
                }

                else -> {
                    val value = token.toIntOrNull()
                    if (value == null || value !in 1..65535) {
                        issues += ValidationIssue(
                            field = "arguments[$index]",
                            message = "Invalid TCP port for Android-local phase-B Nmap mode: $token",
                        )
                    } else {
                        ports += value
                    }
                }
            }
        }

        if (ports.isEmpty()) {
            issues += ValidationIssue("arguments", "Android-local phase-B Nmap mode requires at least one valid TCP port.")
        }

        return if (issues.isEmpty()) {
            ValidationResult.success(ports.toList().sorted())
        } else {
            ValidationResult.failure(issues)
        }
    }

    private fun resolveTimingPolicy(timingToken: String?): LocalTimingPolicy = when (timingToken) {
        "-T0" -> LocalTimingPolicy(connectTimeoutMillis = 2_500, responseTimeoutMillis = 2_500, maxConcurrency = 1)
        "-T1" -> LocalTimingPolicy(connectTimeoutMillis = 2_000, responseTimeoutMillis = 2_000, maxConcurrency = 2)
        "-T2" -> LocalTimingPolicy(connectTimeoutMillis = 1_800, responseTimeoutMillis = 1_800, maxConcurrency = 4)
        "-T4" -> LocalTimingPolicy(connectTimeoutMillis = 1_000, responseTimeoutMillis = 1_000, maxConcurrency = 16)
        "-T5" -> LocalTimingPolicy(connectTimeoutMillis = 750, responseTimeoutMillis = 750, maxConcurrency = 24)
        else -> LocalTimingPolicy(connectTimeoutMillis = 1_500, responseTimeoutMillis = 1_500, maxConcurrency = 8)
    }

    private fun parseDelayMillis(rawValue: String): Long? {
        val value = rawValue.trim().lowercase()
        return when {
            value.endsWith("ms") -> value.removeSuffix("ms").trim().toLongOrNull()
            value.endsWith('s') -> value.removeSuffix("s").trim().toDoubleOrNull()?.times(1_000.0)?.toLong()
            else -> value.toLongOrNull()
        }
    }

    private data class LocalTimingPolicy(
        val connectTimeoutMillis: Int,
        val responseTimeoutMillis: Int,
        val maxConcurrency: Int,
    )

    private data class TargetEndpoint(
        val host: String,
        val port: Int?,
    )

    private fun parseTargetEndpoint(rawTarget: String): TargetEndpoint {
        val target = rawTarget.trim()
        if (target.startsWith("[") && target.contains(']')) {
            val closingBracket = target.indexOf(']')
            val host = target.substring(1, closingBracket)
            val portCandidate = target.substring(closingBracket + 1).takeIf { it.startsWith(":") }
                ?.removePrefix(":")
            return TargetEndpoint(
                host = host,
                port = portCandidate?.toIntOrNull()?.takeIf { it in 1..65535 },
            )
        }

        val lastColon = target.lastIndexOf(':')
        val firstColon = target.indexOf(':')
        return if (lastColon > 0 && firstColon == lastColon) {
            val host = target.substring(0, lastColon)
            val port = target.substring(lastColon + 1).toIntOrNull()?.takeIf { it in 1..65535 }
            TargetEndpoint(host = host, port = port)
        } else {
            TargetEndpoint(host = target, port = null)
        }
    }
}
