package com.thecyberexpert123.nmaptool.remote

import com.thecyberexpert123.nmaptool.contract.ApiErrorResponse
import com.thecyberexpert123.nmaptool.contract.CommandPreview
import com.thecyberexpert123.nmaptool.contract.CommandSafetyPolicy
import com.thecyberexpert123.nmaptool.contract.ExecutionRoute
import com.thecyberexpert123.nmaptool.contract.ExecutorNodeKind
import com.thecyberexpert123.nmaptool.contract.ExecutorTransportKind
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.RunStatus
import com.thecyberexpert123.nmaptool.contract.TargetTopologyClassifier
import com.thecyberexpert123.nmaptool.contract.TargetTopologyScope
import com.thecyberexpert123.nmaptool.contract.TargetValidator
import com.thecyberexpert123.nmaptool.contract.ToolInvocationRequest
import com.thecyberexpert123.nmaptool.contract.ToolInvocationResponse
import com.thecyberexpert123.nmaptool.contract.ToolType
import com.thecyberexpert123.nmaptool.contract.ValidationIssue
import com.thecyberexpert123.nmaptool.contract.allTargetTopologyScopes
import com.thecyberexpert123.nmaptool.contract.toExecutorCapabilityProfile
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.UUID
import java.util.concurrent.TimeUnit

fun main() {
    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080
    val config = ExecutorConfig.fromEnvironment()
    embeddedServer(Netty, host = "0.0.0.0", port = port) {
        nmapExecutorModule(config)
    }.start(wait = true)
}

fun Application.nmapExecutorModule(config: ExecutorConfig) {
    val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = false
    }
    val auditLogger = ExecutorAuditLogger(config.auditLogPath, json)
    val executionEngine = RemoteExecutionEngine(config, auditLogger)

    install(ContentNegotiation) {
        json(json)
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.respond(
                HttpStatusCode.InternalServerError,
                ApiErrorResponse(message = cause.message ?: "Unexpected server error."),
            )
        }
    }

    routing {
        get("/health") {
            call.respond(HealthResponse(status = "ok"))
        }

        get("/api/v1/capabilities") {
            val requestId = UUID.randomUUID().toString()
            authorize(call.request.headers[HttpHeaders.Authorization], config)
                ?.let { message ->
                    auditLogger.append(
                        requestId = requestId,
                        eventType = "capabilities_unauthorized",
                        fields = mapOf("message" to message),
                    )
                    call.respond(HttpStatusCode.Unauthorized, ApiErrorResponse(message, requestId = requestId))
                    return@get
                }
            auditLogger.append(requestId = requestId, eventType = "capabilities_ok")
            call.respond(executionEngine.capabilities())
        }

        post("/api/v1/execute") {
            val requestId = UUID.randomUUID().toString()
            authorize(call.request.headers[HttpHeaders.Authorization], config)
                ?.let { message ->
                    auditLogger.append(
                        requestId = requestId,
                        eventType = "execute_unauthorized",
                        fields = mapOf("message" to message),
                    )
                    call.respond(HttpStatusCode.Unauthorized, ApiErrorResponse(message, requestId = requestId))
                    return@post
                }

            val request = call.receive<ToolInvocationRequest>()
            val issues = validate(request, config)
            if (issues.isNotEmpty()) {
                val message = issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }
                auditLogger.append(
                    requestId = requestId,
                    eventType = "execute_validation_failed",
                    fields = mapOf(
                        "tool" to request.tool.name,
                        "message" to message,
                        "requestedBy" to request.requestedBy.name,
                    ),
                )
                call.respond(
                    HttpStatusCode.BadRequest,
                    ApiErrorResponse(message = message, requestId = requestId),
                )
                return@post
            }

            val response = executionEngine.execute(requestId, request)
            if (response.status == RunStatus.BLOCKED && response.message.contains("maximum concurrent", ignoreCase = true)) {
                call.respond(
                    HttpStatusCode.TooManyRequests,
                    ApiErrorResponse(message = response.message, requestId = response.requestId),
                )
            } else {
                call.respond(response)
            }
        }
    }
}

@kotlinx.serialization.Serializable
private data class HealthResponse(
    val status: String,
)

private fun parseRegexList(rawValue: String): List<Regex> =
    rawValue.split(';')
        .map(String::trim)
        .filter(String::isNotEmpty)
        .map(::Regex)

private fun parseTargetScopeList(rawValue: String): Set<TargetTopologyScope> {
    if (rawValue.isBlank()) {
        return allTargetTopologyScopes.toSet()
    }
    return rawValue.split(';')
        .map(String::trim)
        .filter(String::isNotEmpty)
        .map { value ->
            runCatching { TargetTopologyScope.valueOf(value.uppercase()) }
                .getOrElse { error -> throw IllegalArgumentException("Invalid ALLOWED_TARGET_SCOPES entry: $value", error) }
        }
        .toSet()
}

private fun parseExecutorNodeKind(rawValue: String?): ExecutorNodeKind =
    rawValue?.trim()?.takeIf(String::isNotBlank)?.let { value ->
        runCatching { ExecutorNodeKind.valueOf(value.uppercase()) }
            .getOrElse { error -> throw IllegalArgumentException("Invalid EXECUTOR_NODE_KIND: $value", error) }
    } ?: ExecutorNodeKind.REMOTE_NMAP

private fun parseExecutorTransportKind(rawValue: String?): ExecutorTransportKind =
    rawValue?.trim()?.takeIf(String::isNotBlank)?.let { value ->
        runCatching { ExecutorTransportKind.valueOf(value.uppercase()) }
            .getOrElse { error -> throw IllegalArgumentException("Invalid EXECUTOR_TRANSPORT_KIND: $value", error) }
    } ?: ExecutorTransportKind.HTTPS

private fun authorize(headerValue: String?, config: ExecutorConfig): String? {
    val expectedToken = config.bearerToken.orEmpty()
    if (expectedToken.isBlank()) {
        return null
    }
    return if (headerValue == "Bearer $expectedToken") null else "Missing or invalid bearer token."
}

private fun validate(request: ToolInvocationRequest, config: ExecutorConfig) = buildList {
    addAll(TargetValidator.validate(request.targets))
    addAll(CommandSafetyPolicy.validate(request.tool, request.arguments))
    request.targets.forEachIndexed { index, target ->
        if (!config.isTargetAllowed(target)) {
            add(
                ValidationIssue(
                    field = "targets[$index]",
                    message = "Target is outside the delegated executor policy: $target",
                ),
            )
        }
        if (!config.isTargetScopeAllowed(target)) {
            add(
                ValidationIssue(
                    field = "targets[$index]",
                    message = "Target scope ${TargetTopologyClassifier.classify(target).name} is outside the delegated executor topology policy: $target",
                ),
            )
        }
    }
}

data class ExecutorConfig(
    val bearerToken: String?,
    val executorLabel: String,
    val executorNodeKind: ExecutorNodeKind,
    val executorTransportKind: ExecutorTransportKind,
    val nmapBinary: String,
    val ncatBinary: String,
    val npingBinary: String,
    val executionTimeoutSeconds: Long,
    val maxOutputBytes: Int,
    val allowedTargetRegexes: List<Regex>,
    val allowedTargetScopes: Set<TargetTopologyScope>,
    val maxConcurrentExecutions: Int,
    val auditLogPath: String?,
) {
    fun binaryFor(tool: ToolType): String = when (tool) {
        ToolType.NMAP -> nmapBinary
        ToolType.NCAT -> ncatBinary
        ToolType.NPING -> npingBinary
    }

    fun isTargetAllowed(target: String): Boolean =
        allowedTargetRegexes.isEmpty() || allowedTargetRegexes.any { regex -> regex.matches(target) }

    fun isTargetScopeAllowed(target: String): Boolean =
        TargetTopologyClassifier.classify(target) in allowedTargetScopes

    fun topologySummary(): String = buildString {
        append(
            when (executorNodeKind) {
                ExecutorNodeKind.LAN_AGENT -> "This delegated executor is registered as a LAN agent. "
                ExecutorNodeKind.REMOTE_NMAP -> "This delegated executor is registered as a general Nmap-capable node. "
                ExecutorNodeKind.ANDROID_LOCAL -> "This delegated executor reports an unexpected Android-local node kind. "
                ExecutorNodeKind.UNKNOWN -> "This delegated executor did not declare a recognized node kind. "
            },
        )
        append("Allowed target scopes: ")
        append(allowedTargetScopes.sortedBy { it.ordinal }.joinToString(separator = ", ") { it.name })
        append('.')
    }

    fun targetPolicySummary(): String = buildString {
        append(
            if (allowedTargetRegexes.isEmpty()) {
                "No target regex restriction configured."
            } else {
                "Targets must match one of ${allowedTargetRegexes.size} configured regex policies."
            },
        )
        append(' ')
        append(topologySummary())
    }

    companion object {
        fun fromEnvironment(): ExecutorConfig = ExecutorConfig(
            bearerToken = System.getenv("NMAP_EXECUTOR_TOKEN"),
            executorLabel = System.getenv("EXECUTOR_LABEL")
                ?.trim()
                ?.takeIf(String::isNotBlank)
                ?: System.getenv("HOSTNAME")?.trim()?.takeIf(String::isNotBlank)
                ?: "delegated-executor",
            executorNodeKind = parseExecutorNodeKind(System.getenv("EXECUTOR_NODE_KIND")),
            executorTransportKind = parseExecutorTransportKind(System.getenv("EXECUTOR_TRANSPORT_KIND")),
            nmapBinary = System.getenv("NMAP_BINARY") ?: "nmap",
            ncatBinary = System.getenv("NCAT_BINARY") ?: "ncat",
            npingBinary = System.getenv("NPING_BINARY") ?: "nping",
            executionTimeoutSeconds = System.getenv("EXECUTION_TIMEOUT_SECONDS")?.toLongOrNull() ?: 900L,
            maxOutputBytes = System.getenv("MAX_OUTPUT_BYTES")?.toIntOrNull()?.coerceAtLeast(16_384) ?: 262_144,
            allowedTargetRegexes = parseRegexList(System.getenv("ALLOWED_TARGET_REGEXES").orEmpty()),
            allowedTargetScopes = parseTargetScopeList(System.getenv("ALLOWED_TARGET_SCOPES").orEmpty()),
            maxConcurrentExecutions = System.getenv("MAX_CONCURRENT_EXECUTIONS")
                ?.toIntOrNull()
                ?.coerceIn(1, 64)
                ?: 2,
            auditLogPath = System.getenv("AUDIT_LOG_PATH")
                ?.trim()
                ?.takeIf(String::isNotBlank),
        )
    }
}

class ExecutorAuditLogger(
    auditLogPath: String?,
    private val json: Json,
) {
    private val lock = Any()
    private val auditPath: Path? = auditLogPath?.let(Path::of)

    fun append(
        requestId: String,
        eventType: String,
        fields: Map<String, String?> = emptyMap(),
    ) {
        val path = auditPath ?: return
        runCatching {
            val payload = json.encodeToString(
                kotlinx.serialization.json.JsonObject.serializer(),
                buildJsonObject {
                    put("timestamp", System.currentTimeMillis())
                    put("requestId", requestId)
                    put("eventType", eventType)
                    fields.forEach { (key, value) ->
                        value?.let { put(key, it) }
                    }
                },
            )
            writeLine(path, payload)
        }
    }

    fun appendExecutionEvent(
        requestId: String,
        request: ToolInvocationRequest,
        response: ToolInvocationResponse,
    ) {
        val path = auditPath ?: return
        runCatching {
            val payload = json.encodeToString(
                kotlinx.serialization.json.JsonObject.serializer(),
                buildJsonObject {
                    put("timestamp", System.currentTimeMillis())
                    put("requestId", requestId)
                    put("eventType", "execution_finished")
                    put("executorLabel", response.executorLabel ?: "")
                    put("tool", request.tool.name)
                    put("executionPreference", request.executionPreference.name)
                    put("requestedBy", request.requestedBy.name)
                    put("targetCount", request.targets.size)
                    put("argumentCount", request.arguments.size)
                    put("route", response.route.name)
                    put("status", response.status.name)
                    put("exitCode", response.exitCode?.toString() ?: "")
                    put("durationMillis", (response.finishedAtEpochMillis - response.startedAtEpochMillis).coerceAtLeast(0L).toString())
                    put("stdoutTruncated", response.stdoutTruncated.toString())
                    put("stderrTruncated", response.stderrTruncated.toString())
                    put("nmapXmlOutputTruncated", response.nmapXmlOutputTruncated.toString())
                    put("message", response.message.take(500))
                },
            )
            writeLine(path, payload)
        }
    }

    private fun writeLine(path: Path, payload: String) {
        synchronized(lock) {
            path.parent?.let(Files::createDirectories)
            Files.writeString(
                path,
                payload + System.lineSeparator(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND,
            )
        }
    }
}

class RemoteExecutionEngine(
    private val config: ExecutorConfig,
    private val auditLogger: ExecutorAuditLogger,
) {
    private val executionSemaphore = Semaphore(config.maxConcurrentExecutions)

    fun capabilities(): RemoteCapabilitiesResponse {
        val nmapAvailable = isExecutableAvailable(config.nmapBinary)
        val ncatAvailable = isExecutableAvailable(config.ncatBinary)
        val npingAvailable = isExecutableAvailable(config.npingBinary)
        val privileged = detectPrivileged()
        val requiresAuthentication = config.bearerToken.orEmpty().isNotBlank()
        val response = RemoteCapabilitiesResponse(
            nmapAvailable = nmapAvailable,
            ncatAvailable = ncatAvailable,
            npingAvailable = npingAvailable,
            privileged = privileged,
            requiresAuthentication = requiresAuthentication,
            maxTargetsPerRequest = 64,
            maxArgumentsPerRequest = 128,
            outputCaptureLimitBytes = config.maxOutputBytes,
            targetPolicySummary = config.targetPolicySummary(),
            advisory = buildString {
                append(
                    when (config.executorNodeKind) {
                        ExecutorNodeKind.LAN_AGENT -> "Delegated LAN-agent execution is the preferred compatibility path for private-topology targets from non-root Android devices. "
                        ExecutorNodeKind.REMOTE_NMAP -> "Delegated execution is the preferred compatibility path for non-root Android devices. "
                        ExecutorNodeKind.ANDROID_LOCAL, ExecutorNodeKind.UNKNOWN -> "Delegated execution is available for this node. "
                    },
                )
                append("Privileged scans still depend on how this host is configured. ")
                append("File-writing and process-spawning flags are blocked by policy. ")
                append(config.targetPolicySummary())
            },
            supportsStructuredNmapXml = true,
            executorLabel = config.executorLabel,
            nmapVersion = if (nmapAvailable) detectToolVersion(config.nmapBinary, listOf("--version")) else null,
            ncatVersion = if (ncatAvailable) detectToolVersion(config.ncatBinary, listOf("--version")) else null,
            npingVersion = if (npingAvailable) detectToolVersion(config.npingBinary, listOf("--version")) else null,
            auditLoggingEnabled = config.auditLogPath != null,
            maxConcurrentExecutions = config.maxConcurrentExecutions,
            executorNodeKind = config.executorNodeKind,
            executorTransportKind = config.executorTransportKind,
            allowedTargetScopes = config.allowedTargetScopes.sortedBy { it.ordinal },
            topologySummary = config.topologySummary(),
        )
        return response.copy(executorProfile = response.toExecutorCapabilityProfile())
    }

    suspend fun execute(requestId: String, request: ToolInvocationRequest): ToolInvocationResponse = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        if (!executionSemaphore.tryAcquire()) {
            val response = ToolInvocationResponse(
                route = ExecutionRoute.BLOCKED,
                status = RunStatus.BLOCKED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                stdout = "",
                stderr = "",
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Remote executor is at maximum concurrent execution capacity. Retry later.",
                requestId = requestId,
                executorLabel = config.executorLabel,
            )
            auditLogger.appendExecutionEvent(requestId, request, response)
            return@withContext response
        }

        val binary = config.binaryFor(request.tool)
        if (!isExecutableAvailable(binary)) {
            val response = ToolInvocationResponse(
                route = ExecutionRoute.REMOTE,
                status = RunStatus.FAILED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                stdout = "",
                stderr = "The configured ${request.tool.binaryName} binary is not available on the remote executor host.",
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Remote executor is missing the requested tool.",
                requestId = requestId,
                executorLabel = config.executorLabel,
            )
            auditLogger.appendExecutionEvent(requestId, request, response)
            executionSemaphore.release()
            return@withContext response
        }

        try {
            val structuredFiles = if (request.tool == ToolType.NMAP) {
                StructuredOutputFiles(
                    normalOutputFile = Files.createTempFile("android-nmap-tool-", ".nmap"),
                    xmlOutputFile = Files.createTempFile("android-nmap-tool-", ".xml"),
                )
            } else {
                null
            }

            val response = try {
                val command = buildList {
                    add(binary)
                    addAll(request.arguments)
                    structuredFiles?.let { files ->
                        add("-oN")
                        add(files.normalOutputFile.toString())
                        add("-oX")
                        add(files.xmlOutputFile.toString())
                    }
                    addAll(request.targets)
                }
                val process = ProcessBuilder(command)
                    .redirectErrorStream(false)
                    .start()

                val result = coroutineScope {
                    val stdoutDeferred = async { readCappedText(process.inputStream, config.maxOutputBytes) }
                    val stderrDeferred = async { readCappedText(process.errorStream, config.maxOutputBytes) }
                    val finishedInTime = process.waitFor(config.executionTimeoutSeconds, TimeUnit.SECONDS)
                    if (!finishedInTime) {
                        process.destroyForcibly()
                    }
                    val stdoutCapture = stdoutDeferred.await()
                    val stderrCapture = stderrDeferred.await()
                    val normalOutputCapture = structuredFiles?.normalOutputFile?.let { readCappedFile(it, config.maxOutputBytes) }
                    val xmlOutputCapture = structuredFiles?.xmlOutputFile?.let { readCappedFile(it, config.maxOutputBytes) }
                    ExecutionResult(
                        exitCode = if (finishedInTime) process.exitValue() else null,
                        stdout = normalOutputCapture?.asDisplayText(streamName = "nmap-normal-output")
                            ?: stdoutCapture.asDisplayText(streamName = "stdout"),
                        stderr = buildString {
                            append(stderrCapture.asDisplayText(streamName = "stderr"))
                            if (xmlOutputCapture?.truncated == true) {
                                if (isNotEmpty()) append('\n')
                                append("Structured Nmap XML output exceeded the capture limit and was omitted from the API response.")
                            }
                            if (!finishedInTime) {
                                if (isNotEmpty()) append('\n')
                                append("Execution timed out after ${config.executionTimeoutSeconds} seconds.")
                            }
                        },
                        nmapXmlOutput = xmlOutputCapture
                            ?.takeUnless { it.truncated }
                            ?.content
                            ?.takeIf(String::isNotBlank),
                        stdoutTruncated = normalOutputCapture?.truncated ?: stdoutCapture.truncated,
                        stderrTruncated = stderrCapture.truncated,
                        nmapXmlOutputTruncated = xmlOutputCapture?.truncated == true,
                    )
                }

                ToolInvocationResponse(
                    route = ExecutionRoute.REMOTE,
                    status = if (result.exitCode == 0) RunStatus.SUCCEEDED else RunStatus.FAILED,
                    commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                    exitCode = result.exitCode,
                    stdout = result.stdout,
                    stderr = result.stderr,
                    startedAtEpochMillis = startedAt,
                    finishedAtEpochMillis = System.currentTimeMillis(),
                    message = when {
                        result.exitCode == null -> "Execution exceeded the configured timeout."
                        result.exitCode == 0 -> "Remote execution completed successfully."
                        else -> "Remote execution finished with a non-zero exit code."
                    },
                    nmapXmlOutput = result.nmapXmlOutput,
                    stdoutTruncated = result.stdoutTruncated,
                    stderrTruncated = result.stderrTruncated,
                    nmapXmlOutputTruncated = result.nmapXmlOutputTruncated,
                    requestId = requestId,
                    executorLabel = config.executorLabel,
                )
            } catch (error: Throwable) {
                ToolInvocationResponse(
                    route = ExecutionRoute.REMOTE,
                    status = RunStatus.FAILED,
                    commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                    stdout = "",
                    stderr = error.message.orEmpty(),
                    startedAtEpochMillis = startedAt,
                    finishedAtEpochMillis = System.currentTimeMillis(),
                    message = "Remote execution failed before completion.",
                    requestId = requestId,
                    executorLabel = config.executorLabel,
                )
            } finally {
                structuredFiles?.deleteQuietly()
            }
            auditLogger.appendExecutionEvent(requestId, request, response)
            response
        } finally {
            executionSemaphore.release()
        }
    }

    private fun isExecutableAvailable(binary: String): Boolean {
        if (binary.contains('/')) {
            return Files.isExecutable(Path.of(binary))
        }
        val pathEntries = System.getenv("PATH").orEmpty().split(System.getProperty("path.separator"))
        return pathEntries.any { entry ->
            entry.isNotBlank() && Files.isExecutable(Path.of(entry, binary))
        }
    }

    private fun detectPrivileged(): Boolean {
        if (System.getProperty("user.name") == "root") {
            return true
        }
        return runCatching {
            val probe = ProcessBuilder("id", "-u").start()
            val output = probe.inputStream.bufferedReader().use { it.readText().trim() }
            probe.waitFor(5, TimeUnit.SECONDS)
            output == "0"
        }.getOrDefault(false)
    }

    private fun detectToolVersion(binary: String, versionArguments: List<String>): String? =
        runCatching {
            val process = ProcessBuilder(buildList {
                add(binary)
                addAll(versionArguments)
            })
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly()
            }
            output.lineSequence()
                .map(String::trim)
                .firstOrNull(String::isNotEmpty)
                ?.take(200)
        }.getOrNull()

    private fun readCappedText(inputStream: InputStream, maxBytes: Int): CapturedText {
        inputStream.use { stream ->
            val preserved = ByteArrayOutputStream(maxBytes.coerceAtMost(8_192))
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var totalBytes = 0L
            var truncated = false
            while (true) {
                val bytesRead = stream.read(buffer)
                if (bytesRead < 0) {
                    break
                }
                totalBytes += bytesRead
                val remaining = maxBytes - preserved.size()
                if (remaining > 0) {
                    preserved.write(buffer, 0, bytesRead.coerceAtMost(remaining))
                }
                if (bytesRead > remaining) {
                    truncated = true
                }
            }
            return CapturedText(
                content = preserved.toString(StandardCharsets.UTF_8),
                truncated = truncated || totalBytes > maxBytes,
                originalBytes = totalBytes,
                limitBytes = maxBytes,
            )
        }
    }

    private fun readCappedFile(path: Path, maxBytes: Int): CapturedText? {
        if (!Files.exists(path)) {
            return null
        }
        return readCappedText(Files.newInputStream(path), maxBytes)
    }

    private data class ExecutionResult(
        val exitCode: Int?,
        val stdout: String,
        val stderr: String,
        val nmapXmlOutput: String? = null,
        val stdoutTruncated: Boolean = false,
        val stderrTruncated: Boolean = false,
        val nmapXmlOutputTruncated: Boolean = false,
    )

    private data class StructuredOutputFiles(
        val normalOutputFile: Path,
        val xmlOutputFile: Path,
    ) {
        fun deleteQuietly() {
            runCatching { Files.deleteIfExists(normalOutputFile) }
            runCatching { Files.deleteIfExists(xmlOutputFile) }
        }
    }

    private data class CapturedText(
        val content: String,
        val truncated: Boolean,
        val originalBytes: Long,
        val limitBytes: Int,
    ) {
        fun asDisplayText(streamName: String): String = buildString {
            append(content)
            if (truncated) {
                if (isNotEmpty()) append('\n')
                append("[$streamName truncated after $limitBytes bytes; original stream size was $originalBytes bytes]")
            }
        }
    }
}
