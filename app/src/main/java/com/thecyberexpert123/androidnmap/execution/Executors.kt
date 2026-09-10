package com.thecyberexpert123.androidnmap.execution

import com.thecyberexpert123.androidnmap.settings.RemoteEndpointSettings
import com.thecyberexpert123.nmaptool.contract.AndroidLocalCapabilities
import com.thecyberexpert123.nmaptool.contract.ApiErrorResponse
import com.thecyberexpert123.nmaptool.contract.CommandPreview
import com.thecyberexpert123.nmaptool.contract.ExecutionRoute
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.RunStatus
import com.thecyberexpert123.nmaptool.contract.ToolInvocationRequest
import com.thecyberexpert123.nmaptool.contract.ToolInvocationResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

private const val REMOTE_CAPABILITIES_PATH = "/api/v1/capabilities"
private const val REMOTE_EXECUTE_PATH = "/api/v1/execute"

data class LocalExecutionDecision(
    val canExecute: Boolean,
    val reason: String,
    val preferDelegatedWhenAvailable: Boolean = false,
    val blockers: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
)

interface LocalToolExecutor {
    fun capabilityProfile(): AndroidLocalCapabilities
    suspend fun inspect(request: ToolInvocationRequest): LocalExecutionDecision
    suspend fun execute(request: ToolInvocationRequest): ToolInvocationResponse
}

class DisabledLocalToolExecutor : LocalToolExecutor {
    override fun capabilityProfile(): AndroidLocalCapabilities = AndroidLocalCapabilities(
        available = false,
        networkAvailable = false,
        supportsTcpConnectScan = false,
        supportsUdpDatagramProbes = false,
        advisory = "Android-local execution is disabled in this runtime. Configure a delegated executor for actual scan execution.",
    )

    override suspend fun inspect(request: ToolInvocationRequest): LocalExecutionDecision =
        LocalExecutionDecision(
            canExecute = false,
            reason = "Android-local execution is disabled in this runtime. Configure a delegated executor for actual scan execution.",
            blockers = listOf("Android-local execution is disabled in this runtime."),
        )

    override suspend fun execute(request: ToolInvocationRequest): ToolInvocationResponse {
        val startedAt = System.currentTimeMillis()
        val decision = inspect(request)
        return ToolInvocationResponse(
            route = ExecutionRoute.BLOCKED,
            status = RunStatus.BLOCKED,
            commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
            stdout = "",
            stderr = decision.reason,
            startedAtEpochMillis = startedAt,
            finishedAtEpochMillis = System.currentTimeMillis(),
            message = decision.reason,
        )
    }
}

class RemoteExecutorClient(
    private val json: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = false
    },
) {
    suspend fun fetchCapabilities(settings: RemoteEndpointSettings): Result<RemoteCapabilitiesResponse> =
        withContext(Dispatchers.IO) {
            runCatching {
                val response = request(
                    settings = settings,
                    path = REMOTE_CAPABILITIES_PATH,
                    method = "GET",
                    body = null,
                )
                if (response.code !in 200..299) {
                    throw IllegalStateException(extractErrorMessage(response.body, response.code))
                }
                json.decodeFromString(RemoteCapabilitiesResponse.serializer(), response.body)
            }
        }

    suspend fun execute(
        settings: RemoteEndpointSettings,
        request: ToolInvocationRequest,
    ): ToolInvocationResponse = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        runCatching {
            val response = request(
                settings = settings,
                path = REMOTE_EXECUTE_PATH,
                method = "POST",
                body = json.encodeToString(ToolInvocationRequest.serializer(), request),
            )
            if (response.code !in 200..299) {
                val errorDetails = decodeApiError(response.body, response.code)
                return@withContext ToolInvocationResponse(
                    route = if (response.code == HttpURLConnection.HTTP_UNAVAILABLE || response.code == 429) {
                        ExecutionRoute.BLOCKED
                    } else {
                        ExecutionRoute.REMOTE
                    },
                    status = if (response.code == HttpURLConnection.HTTP_UNAVAILABLE || response.code == 429) {
                        RunStatus.BLOCKED
                    } else {
                        RunStatus.FAILED
                    },
                    commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                    stdout = "",
                    stderr = errorDetails.message,
                    startedAtEpochMillis = startedAt,
                    finishedAtEpochMillis = System.currentTimeMillis(),
                    message = if (response.code == HttpURLConnection.HTTP_UNAVAILABLE || response.code == 429) {
                        "Remote executor could not accept the run right now."
                    } else {
                        "Remote executor rejected the request."
                    },
                    requestId = errorDetails.requestId,
                )
            }
            json.decodeFromString(ToolInvocationResponse.serializer(), response.body)
        }.getOrElse { error ->
            ToolInvocationResponse(
                route = ExecutionRoute.REMOTE,
                status = RunStatus.FAILED,
                commandPreview = CommandPreview.render(request.tool, request.arguments, request.targets),
                stdout = "",
                stderr = error.message.orEmpty(),
                startedAtEpochMillis = startedAt,
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Remote execution failed before a valid response was received.",
            )
        }
    }

    private fun request(
        settings: RemoteEndpointSettings,
        path: String,
        method: String,
        body: String?,
    ): RawResponse {
        val baseUrl = normalizeBaseUrl(settings.baseUrl)
        val endpoint = URL(baseUrl + path)
        val connection = (endpoint.openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 10_000
            readTimeout = 900_000
            setRequestProperty("Accept", "application/json")
            if (settings.bearerToken.isNotBlank()) {
                setRequestProperty("Authorization", "Bearer ${settings.bearerToken}")
            }
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                outputStream.bufferedWriter().use { writer ->
                    writer.write(body)
                }
            }
        }

        return connection.use { activeConnection ->
            val code = activeConnection.responseCode
            val bodyStream = activeConnection.inputStreamOrError()
            val responseBody = bodyStream?.bufferedReader()?.use { it.readText() }.orEmpty()
            RawResponse(code = code, body = responseBody)
        }
    }

    private fun HttpURLConnection.inputStreamOrError() =
        try {
            inputStream
        } catch (_: Exception) {
            errorStream
        }

    private fun normalizeBaseUrl(rawUrl: String): String {
        val candidate = rawUrl.trim().removeSuffix("/")
        require(candidate.isNotBlank()) { "Remote executor base URL is required." }
        val uri = URI(candidate)
        require(uri.scheme == "http" || uri.scheme == "https") {
            "Remote executor URL must use http or https."
        }
        require(!uri.host.isNullOrBlank()) { "Remote executor URL must include a host." }
        return candidate
    }

    private fun extractErrorMessage(body: String, code: Int): String = decodeApiError(body, code).message

    private fun decodeApiError(body: String, code: Int): DecodedApiError =
        try {
            val apiError = json.decodeFromString(ApiErrorResponse.serializer(), body)
            DecodedApiError(
                message = buildString {
                    append("HTTP $code: ${apiError.message}")
                    apiError.requestId?.takeIf(String::isNotBlank)?.let { requestId ->
                        append(" (request $requestId)")
                    }
                },
                requestId = apiError.requestId,
            )
        } catch (_: SerializationException) {
            DecodedApiError(
                message = if (body.isBlank()) {
                    "HTTP $code: no error body returned by delegated executor."
                } else {
                    "HTTP $code: $body"
                },
            )
        }

    private data class RawResponse(
        val code: Int,
        val body: String,
    )

    private data class DecodedApiError(
        val message: String,
        val requestId: String? = null,
    )
}

private inline fun <T : HttpURLConnection?, R> T.use(block: (T) -> R): R =
    try {
        block(this)
    } finally {
        this?.disconnect()
    }
