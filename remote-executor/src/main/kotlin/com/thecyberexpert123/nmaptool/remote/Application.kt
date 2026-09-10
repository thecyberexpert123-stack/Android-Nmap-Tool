package com.thecyberexpert123.nmaptool.remote

import com.thecyberexpert123.nmaptool.contract.ApiErrorResponse
import com.thecyberexpert123.nmaptool.contract.CommandPreview
import com.thecyberexpert123.nmaptool.contract.CommandSafetyPolicy
import com.thecyberexpert123.nmaptool.contract.ExecutionRoute
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.RunStatus
import com.thecyberexpert123.nmaptool.contract.TargetValidator
import com.thecyberexpert123.nmaptool.contract.ToolInvocationRequest
import com.thecyberexpert123.nmaptool.contract.ToolInvocationResponse
import com.thecyberexpert123.nmaptool.contract.ToolType
import com.thecyberexpert123.nmaptool.contract.ValidationIssue
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
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
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
    val executionEngine = RemoteExecutionEngine(config)

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
            authorize(call.request.headers[HttpHeaders.Authorization], config)
                ?.let { message ->
                    call.respond(HttpStatusCode.Unauthorized, ApiErrorResponse(message))
                    return@get
                }
            call.respond(executionEngine.capabilities())
        }

        post("/api/v1/execute") {
            authorize(call.request.headers[HttpHeaders.Authorization], config)
                ?.let { message ->
                    call.respond(HttpStatusCode.Unauthorized, ApiErrorResponse(message))
                    return@post
                }

            val request = call.receive<ToolInvocationRequest>()
            val issues = validate(request, config)
            if (issues.isNotEmpty()) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ApiErrorResponse(message = issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }),
                )
                return@post
            }

            call.respond(executionEngine.execute(request))
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
                    message = "Target is outside the remote executor policy: $target",
                ),
            )
        }
    }
}

data class ExecutorConfig(
    val bearerToken: String?,
    val nmapBinary: String,
    val ncatBinary: String,
    val npingBinary: String,
    val executionTimeoutSeconds: Long,
    val maxOutputBytes: Int,
    val allowedTargetRegexes: List<Regex>,
) {
    fun binaryFor(tool: ToolType): String = when (tool) {
        ToolType.NMAP -> nmapBinary
        ToolType.NCAT -> ncatBinary
        ToolType.NPING -> npingBinary
    }

    fun isTargetAllowed(target: String): Boolean =
        allowedTargetRegexes.isEmpty() || allowedTargetRegexes.any { regex -> regex.matches(target) }

    fun targetPolicySummary(): String =
        if (allowedTargetRegexes.isEmpty()) {
            "No target regex restriction configured."
        } else {
            "Targets must match one of ${allowedTargetRegexes.size} configured regex policies."
        }

    companion object {
        fun fromEnvironment(): ExecutorConfig = ExecutorConfig(
            bearerToken = System.getenv("NMAP_EXECUTOR_TOKEN"),
            nmapBinary = System.getenv("NMAP_BINARY") ?: "nmap",
            ncatBinary = System.getenv("NCAT_BINARY") ?: "ncat",
            npingBinary = System.getenv("NPING_BINARY") ?: "nping",
            executionTimeoutSeconds = System.getenv("EXECUTION_TIMEOUT_SECONDS")?.toLongOrNull() ?: 900L,
            maxOutputBytes = System.getenv("MAX_OUTPUT_BYTES")?.toIntOrNull()?.coerceAtLeast(16_384) ?: 262_144,
            allowedTargetRegexes = parseRegexList(System.getenv("ALLOWED_TARGET_REGEXES").orEmpty()),
        )
    }
}

class RemoteExecutionEngine(
    private val config: ExecutorConfig,
) {
    fun capabilities(): RemoteCapabilitiesResponse = RemoteCapabilitiesResponse(
        nmapAvailable = isExecutableAvailable(config.nmapBinary),
        ncatAvailable = isExecutableAvailable(config.ncatBinary),
        npingAvailable = isExecutableAvailable(config.npingBinary),
        privileged = detectPrivileged(),
        requiresAuthentication = config.bearerToken.orEmpty().isNotBlank(),
        maxTargetsPerRequest = 64,
        maxArgumentsPerRequest = 128,
        outputCaptureLimitBytes = config.maxOutputBytes,
        targetPolicySummary = config.targetPolicySummary(),
        advisory = buildString {
            append("Remote execution is the preferred compatibility path for non-root Android devices. ")
            append("Privileged scans still depend on how this host is configured. ")
            append("File-writing and process-spawning flags are blocked by policy. ")
            append(config.targetPolicySummary())
        },
        supportsStructuredNmapXml = true,
    )

    suspend fun execute(request: ToolInvocationRequest): ToolInvocationResponse = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val binary = config.binaryFor(request.tool)
        if (!isExecutableAvailable(binary)) {
            return@withContext ToolInvocationResponse(
                route = ExecutionRoute.REMOTE,
                status = RunStatus.FAILED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                stdout = "",
                stderr = "The configured ${request.tool.binaryName} binary is not available on the remote executor host.",
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Remote executor is missing the requested tool.",
            )
        }

        val structuredFiles = if (request.tool == ToolType.NMAP) {
            StructuredOutputFiles(
                normalOutputFile = Files.createTempFile("android-nmap-tool-", ".nmap"),
                xmlOutputFile = Files.createTempFile("android-nmap-tool-", ".xml"),
            )
        } else {
            null
        }

        try {
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
            )
        } finally {
            structuredFiles?.deleteQuietly()
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
