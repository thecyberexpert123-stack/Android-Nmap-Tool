package com.thecyberexpert123.androidnmap.execution

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.thecyberexpert123.nmaptool.contract.AndroidLocalCapabilities
import com.thecyberexpert123.nmaptool.contract.AndroidLocalExecutionPlanner
import com.thecyberexpert123.nmaptool.contract.AndroidLocalNcatPlan
import com.thecyberexpert123.nmaptool.contract.AndroidLocalNmapPlan
import com.thecyberexpert123.nmaptool.contract.AndroidLocalNpingMode
import com.thecyberexpert123.nmaptool.contract.AndroidLocalNpingPlan
import com.thecyberexpert123.nmaptool.contract.CommandPreview
import com.thecyberexpert123.nmaptool.contract.ExecutionRoute
import com.thecyberexpert123.nmaptool.contract.RunStatus
import com.thecyberexpert123.nmaptool.contract.ToolInvocationRequest
import com.thecyberexpert123.nmaptool.contract.ToolInvocationResponse
import com.thecyberexpert123.nmaptool.contract.ToolType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Locale
import kotlin.math.roundToLong

private const val LOCAL_BANNER_CAPTURE_LIMIT = 4096
private val commonServiceNames = mapOf(
    7 to "echo",
    21 to "ftp",
    22 to "ssh",
    23 to "telnet",
    25 to "smtp",
    53 to "domain",
    80 to "http",
    110 to "pop3",
    111 to "rpcbind",
    123 to "ntp",
    135 to "msrpc",
    139 to "netbios-ssn",
    143 to "imap",
    389 to "ldap",
    443 to "https",
    445 to "microsoft-ds",
    465 to "smtps",
    587 to "submission",
    631 to "ipp",
    993 to "imaps",
    995 to "pop3s",
    1080 to "socks",
    1433 to "ms-sql-s",
    1521 to "oracle",
    1723 to "pptp",
    2049 to "nfs",
    2375 to "docker",
    2376 to "docker-ssl",
    3000 to "http-alt",
    3306 to "mysql",
    3389 to "ms-wbt-server",
    5000 to "upnp",
    5060 to "sip",
    5061 to "sips",
    5432 to "postgresql",
    5601 to "kibana",
    5672 to "amqp",
    5900 to "vnc",
    5984 to "couchdb",
    6379 to "redis",
    6443 to "https-alt",
    7001 to "weblogic",
    8000 to "http-alt",
    8008 to "http-alt",
    8080 to "http-proxy",
    8081 to "http-alt",
    8443 to "https-alt",
    8888 to "http-alt",
    9000 to "cslistener",
    9090 to "http-alt",
    9092 to "kafka",
    9200 to "elasticsearch",
    9300 to "elasticsearch-node",
    9999 to "abyss",
    10000 to "webmin",
    11211 to "memcached",
    15672 to "amqp-http",
    27017 to "mongodb",
)

class AndroidLocalToolExecutor(
    context: Context,
) : LocalToolExecutor {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)

    override fun capabilityProfile(): AndroidLocalCapabilities {
        val activeNetwork = connectivityManager?.activeNetwork
        return AndroidLocalCapabilities(
            available = connectivityManager != null,
            networkAvailable = activeNetwork != null,
            activeNetworkSummary = activeNetwork?.let(::describeNetworkSummary) ?: "No active default network",
            supportsServiceDetection = connectivityManager != null,
        )
    }

    override suspend fun inspect(request: ToolInvocationRequest): LocalExecutionDecision {
        val assessment = AndroidLocalExecutionPlanner.assess(
            tool = request.tool,
            targets = request.targets,
            arguments = request.arguments,
            capabilities = capabilityProfile(),
        )
        return LocalExecutionDecision(
            canExecute = assessment.supported,
            reason = assessment.summary,
            blockers = assessment.blockers,
            warnings = assessment.warnings,
            notes = assessment.notes,
        )
    }

    override suspend fun execute(request: ToolInvocationRequest): ToolInvocationResponse {
        val startedAt = System.currentTimeMillis()
        val network = connectivityManager?.activeNetwork
        val decision = inspect(request)
        if (!decision.canExecute || network == null) {
            return ToolInvocationResponse(
                route = ExecutionRoute.BLOCKED,
                status = RunStatus.BLOCKED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                stdout = "",
                stderr = buildList {
                    add(decision.reason)
                    addAll(decision.blockers)
                }.distinct().joinToString(separator = "\n"),
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = decision.reason,
            )
        }

        return when (request.tool) {
            ToolType.NMAP -> executeLocalNmap(startedAt, network, request)
            ToolType.NCAT -> executeLocalNcat(startedAt, network, request)
            ToolType.NPING -> executeLocalNping(startedAt, network, request)
        }
    }

    private suspend fun executeLocalNmap(
        startedAt: Long,
        network: Network,
        request: ToolInvocationRequest,
    ): ToolInvocationResponse = withContext(Dispatchers.IO) {
        val capabilities = capabilityProfile()
        val plan = AndroidLocalExecutionPlanner.createNmapPlan(request.arguments, capabilities).value
            ?: return@withContext buildUnexpectedLocalFailure(startedAt, request, "Android-local Nmap plan became invalid before execution.")
        runCatching {
            val targetResults = request.targets.map { target ->
                scanTcpTarget(network, target, plan, capabilities)
            }
            val hostsUp = targetResults.count { it.hostResponsive }
            val openPorts = targetResults.sumOf { result -> result.openPorts.size }
            val serviceDetectionsPerformed = targetResults.sumOf { it.serviceDetectionsPerformed }
            val serviceDetectionsSkipped = targetResults.sumOf { it.serviceDetectionsSkipped }
            val stdout = buildString {
                targetResults.forEach { result ->
                    appendLine("Nmap scan report for ${result.target}")
                    if (result.hostResponsive) {
                        val latencyText = result.bestLatencyMillis?.let { formatLatency(it) }
                        appendLine(
                            if (latencyText == null) {
                                "Host is up."
                            } else {
                                "Host is up ($latencyText latency)."
                            },
                        )
                        if (result.openPorts.isNotEmpty()) {
                            appendLine(if (plan.enableServiceDetection) "PORT     STATE SERVICE VERSION" else "PORT     STATE SERVICE")
                            result.openPorts.forEach { portResult ->
                                appendLine(
                                    buildString {
                                        append("${portResult.port}/tcp open ${portResult.service}")
                                        portResult.details.takeIf(String::isNotBlank)?.let {
                                            append(' ')
                                            append(it)
                                        }
                                    },
                                )
                            }
                        }
                        if (result.closedPortCount > 0) {
                            appendLine("Not shown: ${result.closedPortCount} closed tcp ports")
                        }
                        if (result.filteredPortCount > 0) {
                            appendLine(
                                "Note: ${result.filteredPortCount} ports produced no definitive response in Android-local connect probing.",
                            )
                        }
                    } else {
                        appendLine("Host appears down or silently filtered from Android-local connect probing.")
                    }
                    appendLine()
                }
                appendLine(
                    "Nmap done: ${request.targets.size} IP addresses ($hostsUp hosts up) scanned in ${formatElapsedSeconds(System.currentTimeMillis() - startedAt)} seconds",
                )
            }.trimEnd()
            val stderrLines = buildList {
                if (plan.usedCuratedPortCatalog) {
                    add(
                        if (plan.topPortsRequested != null) {
                            "Android-local --top-ports used the app's curated TCP port catalog rather than Nmap's exact service-frequency database."
                        } else {
                            "Android-local -F used the app's curated fast TCP port catalog rather than Nmap's exact service-frequency database."
                        },
                    )
                }
                if (!plan.skipHostDiscovery) {
                    add("Missing -Pn was handled with connect-based reachability inference rather than raw host discovery.")
                }
                if (plan.enableServiceDetection) {
                    add("Android-local -sV performed curated service identification rather than full Nmap version detection.")
                    add("Curated service detections attempted: $serviceDetectionsPerformed")
                    if (serviceDetectionsSkipped > 0) {
                        add("Open endpoints left with port-based naming after the per-run service-detection limit: $serviceDetectionsSkipped")
                    }
                }
                targetResults.forEach { result ->
                    addAll(result.warnings)
                    result.error?.let(::add)
                }
            }
            val attemptedTargets = targetResults.count { it.attempted }
            val finishedAt = System.currentTimeMillis()
            ToolInvocationResponse(
                route = ExecutionRoute.LOCAL,
                status = if (attemptedTargets > 0) RunStatus.SUCCEEDED else RunStatus.FAILED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                exitCode = if (attemptedTargets > 0) 0 else 1,
                stdout = stdout,
                stderr = stderrLines.distinct().joinToString(separator = "\n"),
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = finishedAt,
                message = buildString {
                    append("Android-local TCP connect scan completed against ${request.targets.size} target(s). ")
                    append("Open TCP ports found: $openPorts. ")
                    if (plan.enableServiceDetection) {
                        append("Curated service identification attempted on $serviceDetectionsPerformed open endpoint(s). ")
                    }
                    append("This result reflects socket-level probing only; raw-packet Nmap features remain delegated-only.")
                    if (attemptedTargets == 0) {
                        append(" No targets could be resolved or probed on the active Android network.")
                    }
                },
            )
        }.getOrElse { error ->
            ToolInvocationResponse(
                route = ExecutionRoute.LOCAL,
                status = RunStatus.FAILED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                exitCode = 1,
                stdout = "",
                stderr = error.message.orEmpty(),
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Android-local TCP connect scan failed before completion.",
            )
        }
    }

    private suspend fun executeLocalNcat(
        startedAt: Long,
        network: Network,
        request: ToolInvocationRequest,
    ): ToolInvocationResponse = withContext(Dispatchers.IO) {
        val plan = AndroidLocalExecutionPlanner.createNcatPlan(request.targets, request.arguments).value
            ?: return@withContext buildUnexpectedLocalFailure(startedAt, request, "Android-local Ncat plan became invalid before execution.")
        runCatching {
            val targetAddress = resolveTargetAddress(network, plan.host)
                ?: return@runCatching ToolInvocationResponse(
                    route = ExecutionRoute.LOCAL,
                    status = RunStatus.FAILED,
                    commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                    exitCode = 1,
                    stdout = "",
                    stderr = "Failed to resolve ${plan.host} on the active Android network.",
                    startedAtEpochMillis = startedAt,
                    finishedAtEpochMillis = System.currentTimeMillis(),
                    message = "Android-local Ncat session probe could not resolve the target host.",
                )
            val probe = openTcpSession(network, targetAddress, plan)
            val finishedAt = System.currentTimeMillis()
            when {
                probe.connected -> ToolInvocationResponse(
                    route = ExecutionRoute.LOCAL,
                    status = RunStatus.SUCCEEDED,
                    commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                    exitCode = 0,
                    stdout = buildString {
                        appendLine("Ncat: Connected to ${plan.host}:${plan.port}")
                        probe.banner?.takeIf(String::isNotBlank)?.let(::appendLine)
                    }.trimEnd(),
                    stderr = when {
                        probe.failureMessage?.isNotBlank() == true -> probe.failureMessage
                        probe.banner.isNullOrBlank() && !plan.zeroIo -> "No immediate banner was captured before the read timeout expired."
                        else -> ""
                    },
                    startedAtEpochMillis = startedAt,
                    finishedAtEpochMillis = finishedAt,
                    message = buildString {
                        append("Android-local TCP session probe completed. ")
                        append(
                            if (plan.zeroIo) {
                                "Zero-I/O mode was requested, so no banner read was attempted."
                            } else if (probe.banner.isNullOrBlank()) {
                                "The session connected, but no immediate banner was captured."
                            } else {
                                "A banner was captured from the remote service."
                            },
                        )
                    },
                )

                else -> ToolInvocationResponse(
                    route = ExecutionRoute.LOCAL,
                    status = RunStatus.FAILED,
                    commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                    exitCode = 1,
                    stdout = "",
                    stderr = probe.failureMessage.orEmpty(),
                    startedAtEpochMillis = startedAt,
                    finishedAtEpochMillis = finishedAt,
                    message = "Android-local TCP session probe did not establish a connection.",
                )
            }
        }.getOrElse { error ->
            ToolInvocationResponse(
                route = ExecutionRoute.LOCAL,
                status = RunStatus.FAILED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                exitCode = 1,
                stdout = "",
                stderr = error.message.orEmpty(),
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Android-local Ncat session probe failed before completion.",
            )
        }
    }

    private suspend fun executeLocalNping(
        startedAt: Long,
        network: Network,
        request: ToolInvocationRequest,
    ): ToolInvocationResponse = withContext(Dispatchers.IO) {
        val capabilities = capabilityProfile()
        val plan = AndroidLocalExecutionPlanner.createNpingPlan(request.targets, request.arguments, capabilities).value
            ?: return@withContext buildUnexpectedLocalFailure(startedAt, request, "Android-local Nping plan became invalid before execution.")
        runCatching {
            val targetAddress = resolveTargetAddress(network, plan.host)
                ?: return@runCatching ToolInvocationResponse(
                    route = ExecutionRoute.LOCAL,
                    status = RunStatus.FAILED,
                    commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                    exitCode = 1,
                    stdout = "",
                    stderr = "Failed to resolve ${plan.host} on the active Android network.",
                    startedAtEpochMillis = startedAt,
                    finishedAtEpochMillis = System.currentTimeMillis(),
                    message = "Android-local Nping probe could not resolve the target host.",
                )
            val sampleResults = mutableListOf<ProbeSample>()
            repeat(plan.count) { attemptIndex ->
                sampleResults += when (plan.mode) {
                    AndroidLocalNpingMode.TCP_CONNECT -> probeTcpConnect(network, targetAddress, plan.port, plan.connectTimeoutMillis)
                    AndroidLocalNpingMode.UDP -> probeUdp(network, targetAddress, plan)
                }
                if (attemptIndex < plan.count - 1 && plan.delayMillis > 0L) {
                    delay(plan.delayMillis)
                }
            }
            val receivedSamples = sampleResults.filter { it.responded }
            val rtts = receivedSamples.mapNotNull { it.rttMillis }
            val failedCount = plan.count - receivedSamples.size
            val finishedAt = System.currentTimeMillis()
            ToolInvocationResponse(
                route = ExecutionRoute.LOCAL,
                status = RunStatus.SUCCEEDED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                exitCode = 0,
                stdout = buildString {
                    appendLine(
                        when (plan.mode) {
                            AndroidLocalNpingMode.TCP_CONNECT -> "TCP connect responses: open=${sampleResults.count { it.outcome == ProbeOutcome.OPEN }}, refused=${sampleResults.count { it.outcome == ProbeOutcome.CLOSED }}, timeout=${sampleResults.count { it.outcome == ProbeOutcome.TIMEOUT }}"
                            AndroidLocalNpingMode.UDP -> "UDP application responses: replied=${sampleResults.count { it.outcome == ProbeOutcome.OPEN }}, port-unreachable=${sampleResults.count { it.outcome == ProbeOutcome.CLOSED }}, timeout=${sampleResults.count { it.outcome == ProbeOutcome.TIMEOUT }}"
                        },
                    )
                    if (rtts.isNotEmpty()) {
                        appendLine(
                            "Max rtt: ${formatLatency(rtts.maxOrNull() ?: 0L)} | Min rtt: ${formatLatency(rtts.minOrNull() ?: 0L)} | Avg rtt: ${formatLatency((rtts.average()).roundToLong())}",
                        )
                    }
                    appendLine("Raw packets sent: ${plan.count} | Rcvd: ${receivedSamples.size} | Lost: $failedCount")
                }.trimEnd(),
                stderr = when (plan.mode) {
                    AndroidLocalNpingMode.TCP_CONNECT -> "Android-local Nping measured TCP connect timing rather than raw packet RTT."
                    AndroidLocalNpingMode.UDP -> "UDP no-response samples are inconclusive on stock Android because the app does not have full raw ICMP visibility."
                },
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = finishedAt,
                message = when (plan.mode) {
                    AndroidLocalNpingMode.TCP_CONNECT -> "Android-local TCP connect latency probe completed with ${receivedSamples.size} of ${plan.count} definitive responses."
                    AndroidLocalNpingMode.UDP -> "Android-local UDP application probe completed with ${receivedSamples.size} of ${plan.count} responses; silent samples remain inconclusive."
                },
            )
        }.getOrElse { error ->
            ToolInvocationResponse(
                route = ExecutionRoute.LOCAL,
                status = RunStatus.FAILED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                exitCode = 1,
                stdout = "",
                stderr = error.message.orEmpty(),
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Android-local Nping probe failed before completion.",
            )
        }
    }

    private suspend fun scanTcpTarget(
        network: Network,
        target: String,
        plan: AndroidLocalNmapPlan,
        capabilities: AndroidLocalCapabilities,
    ): LocalTargetScanResult {
        val address = resolveTargetAddress(network, target)
            ?: return LocalTargetScanResult(
                target = target,
                attempted = false,
                hostResponsive = false,
                openPorts = emptyList(),
                closedPortCount = 0,
                filteredPortCount = 0,
                bestLatencyMillis = null,
                error = "Failed to resolve $target on the active Android network.",
            )
        val semaphore = Semaphore(plan.maxConcurrency)
        val portResults = coroutineScope {
            plan.ports.map { port ->
                async(Dispatchers.IO) {
                    semaphore.acquire()
                    try {
                        probeTcpConnect(network, address, port, plan.connectTimeoutMillis)
                    } finally {
                        semaphore.release()
                    }
                }
            }.awaitAll()
        }.sortedBy { it.port }
        val openPortSamples = portResults.filter { it.outcome == ProbeOutcome.OPEN }
        val serviceDetection = if (plan.enableServiceDetection && openPortSamples.isNotEmpty()) {
            AndroidLocalServiceDetector.detectOpenTcpServices(
                network = network,
                targetLabel = target,
                targetAddress = address,
                openPorts = openPortSamples.map { it.port },
                connectTimeoutMillis = plan.connectTimeoutMillis,
                readTimeoutMillis = plan.serviceReadTimeoutMillis,
                maxConcurrency = plan.maxConcurrency,
                maxDetections = capabilities.maxServiceDetectionsPerRun,
            )
        } else {
            null
        }
        val openPorts = openPortSamples.map { portSample ->
            val detected = serviceDetection?.findingsByPort?.get(portSample.port)
            LocalOpenPortResult(
                port = portSample.port,
                service = detected?.serviceName ?: commonServiceNames[portSample.port].orEmpty().ifBlank { "unknown" },
                details = detected?.details.orEmpty(),
                rttMillis = portSample.rttMillis,
            )
        }
        return LocalTargetScanResult(
            target = target,
            attempted = true,
            hostResponsive = portResults.any { it.outcome == ProbeOutcome.OPEN || it.outcome == ProbeOutcome.CLOSED },
            openPorts = openPorts,
            closedPortCount = portResults.count { it.outcome == ProbeOutcome.CLOSED },
            filteredPortCount = portResults.count { it.outcome == ProbeOutcome.TIMEOUT },
            bestLatencyMillis = portResults.mapNotNull { it.rttMillis }.minOrNull(),
            warnings = serviceDetection?.warnings.orEmpty(),
            serviceDetectionsPerformed = serviceDetection?.attemptedCount ?: 0,
            serviceDetectionsSkipped = serviceDetection?.skippedCount ?: 0,
            error = null,
        )
    }

    private fun resolveTargetAddress(network: Network, rawTarget: String): InetAddress? =
        runCatching {
            network.getAllByName(rawTarget.trim()).firstOrNull()
        }.getOrNull()

    private fun openTcpSession(
        network: Network,
        targetAddress: InetAddress,
        plan: AndroidLocalNcatPlan,
    ): TcpSessionProbeResult {
        val socket = network.socketFactory.createSocket() as Socket
        return try {
            socket.soTimeout = plan.readTimeoutMillis
            socket.connect(InetSocketAddress(targetAddress, plan.port), plan.connectTimeoutMillis)
            val (banner, bannerFailureMessage) = if (plan.zeroIo) {
                null to null
            } else {
                runCatching {
                    val buffer = ByteArray(LOCAL_BANNER_CAPTURE_LIMIT)
                    val read = socket.getInputStream().read(buffer)
                    if (read <= 0) null else String(buffer, 0, read, Charsets.UTF_8).trim()
                }.fold(
                    onSuccess = { capturedBanner -> capturedBanner to null },
                    onFailure = { error ->
                        if (error is SocketTimeoutException) {
                            null to null
                        } else {
                            null to (error.message ?: "Banner read failed after the TCP session connected.")
                        }
                    },
                )
            }
            TcpSessionProbeResult(
                connected = true,
                banner = banner,
                failureMessage = bannerFailureMessage,
            )
        } catch (error: Exception) {
            TcpSessionProbeResult(connected = false, failureMessage = error.message ?: "Connection failed.")
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun probeTcpConnect(
        network: Network,
        targetAddress: InetAddress,
        port: Int,
        timeoutMillis: Int,
    ): ProbeSample {
        val socket = network.socketFactory.createSocket() as Socket
        val startedAtNanos = System.nanoTime()
        return try {
            socket.connect(InetSocketAddress(targetAddress, port), timeoutMillis)
            ProbeSample(
                port = port,
                outcome = ProbeOutcome.OPEN,
                responded = true,
                rttMillis = elapsedMillis(startedAtNanos),
            )
        } catch (error: ConnectException) {
            ProbeSample(
                port = port,
                outcome = ProbeOutcome.CLOSED,
                responded = true,
                rttMillis = elapsedMillis(startedAtNanos),
            )
        } catch (_: NoRouteToHostException) {
            ProbeSample(port = port, outcome = ProbeOutcome.TIMEOUT, responded = false)
        } catch (_: SocketTimeoutException) {
            ProbeSample(port = port, outcome = ProbeOutcome.TIMEOUT, responded = false)
        } catch (_: IOException) {
            ProbeSample(port = port, outcome = ProbeOutcome.TIMEOUT, responded = false)
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun probeUdp(
        network: Network,
        targetAddress: InetAddress,
        plan: AndroidLocalNpingPlan,
    ): ProbeSample {
        val payload = udpPayloadForPort(plan.port)
        val socket = DatagramSocket(null)
        val startedAtNanos = System.nanoTime()
        return try {
            network.bindSocket(socket)
            socket.soTimeout = plan.responseTimeoutMillis
            socket.connect(InetSocketAddress(targetAddress, plan.port))
            socket.send(DatagramPacket(payload, payload.size))
            val responseBuffer = ByteArray(LOCAL_BANNER_CAPTURE_LIMIT)
            val packet = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(packet)
            ProbeSample(
                port = plan.port,
                outcome = ProbeOutcome.OPEN,
                responded = true,
                rttMillis = elapsedMillis(startedAtNanos),
            )
        } catch (_: PortUnreachableException) {
            ProbeSample(
                port = plan.port,
                outcome = ProbeOutcome.CLOSED,
                responded = true,
                rttMillis = elapsedMillis(startedAtNanos),
            )
        } catch (_: SocketTimeoutException) {
            ProbeSample(port = plan.port, outcome = ProbeOutcome.TIMEOUT, responded = false)
        } catch (_: IOException) {
            ProbeSample(port = plan.port, outcome = ProbeOutcome.TIMEOUT, responded = false)
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun udpPayloadForPort(port: Int): ByteArray = when (port) {
        53 -> byteArrayOf(
            0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 0x00.toByte(),
            0x00.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
        )
        123 -> byteArrayOf(0x1b.toByte())
        else -> "android-nmap-tool".toByteArray(Charsets.UTF_8)
    }

    private fun elapsedMillis(startedAtNanos: Long): Long =
        ((System.nanoTime() - startedAtNanos).toDouble() / 1_000_000.0).roundToLong().coerceAtLeast(1L)

    private fun formatLatency(valueMillis: Long): String = "${valueMillis}ms"

    private fun formatElapsedSeconds(durationMillis: Long): String =
        String.format(Locale.US, "%.2f", durationMillis.coerceAtLeast(0L).toDouble() / 1_000.0)

    private fun describeNetworkSummary(network: Network): String {
        val capabilities = connectivityManager?.getNetworkCapabilities(network)
        if (capabilities == null) {
            return "Active network available"
        }
        val transports = buildList {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("Wi-Fi")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("Cellular")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("Ethernet")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add("Bluetooth")
        }.ifEmpty { listOf("Unknown transport") }
        val validation = if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
            "validated internet"
        } else {
            "unvalidated or local-only"
        }
        return transports.joinToString(separator = ", ") + " — " + validation
    }

    private fun buildUnexpectedLocalFailure(
        startedAt: Long,
        request: ToolInvocationRequest,
        message: String,
    ) = ToolInvocationResponse(
        route = ExecutionRoute.LOCAL,
        status = RunStatus.FAILED,
        commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
        exitCode = 1,
        stdout = "",
        stderr = message,
        startedAtEpochMillis = startedAt,
        finishedAtEpochMillis = System.currentTimeMillis(),
        message = message,
    )

    private data class LocalTargetScanResult(
        val target: String,
        val attempted: Boolean,
        val hostResponsive: Boolean,
        val openPorts: List<LocalOpenPortResult>,
        val closedPortCount: Int,
        val filteredPortCount: Int,
        val bestLatencyMillis: Long?,
        val warnings: List<String> = emptyList(),
        val serviceDetectionsPerformed: Int = 0,
        val serviceDetectionsSkipped: Int = 0,
        val error: String?,
    )

    private data class LocalOpenPortResult(
        val port: Int,
        val service: String,
        val details: String = "",
        val rttMillis: Long? = null,
    )

    private data class TcpSessionProbeResult(
        val connected: Boolean,
        val banner: String? = null,
        val failureMessage: String? = null,
    )

    private data class ProbeSample(
        val port: Int,
        val outcome: ProbeOutcome,
        val responded: Boolean,
        val rttMillis: Long? = null,
    )

    private enum class ProbeOutcome {
        OPEN,
        CLOSED,
        TIMEOUT,
    }
}
