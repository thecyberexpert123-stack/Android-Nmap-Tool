package com.thecyberexpert123.androidnmap.data

import com.thecyberexpert123.androidnmap.execution.LocalToolExecutor
import com.thecyberexpert123.androidnmap.execution.RemoteExecutorClient
import com.thecyberexpert123.androidnmap.settings.RemoteEndpointSettings
import com.thecyberexpert123.androidnmap.settings.RemoteSettingsStore
import com.thecyberexpert123.nmaptool.contract.AndroidLocalCapabilities
import com.thecyberexpert123.nmaptool.contract.CommandPreview
import com.thecyberexpert123.nmaptool.contract.ExecutionPreference
import com.thecyberexpert123.nmaptool.contract.ExecutionRoute
import com.thecyberexpert123.nmaptool.contract.InvocationFactory
import com.thecyberexpert123.nmaptool.contract.PortFinding
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.RunStatus
import com.thecyberexpert123.nmaptool.contract.RunTrigger
import com.thecyberexpert123.nmaptool.contract.ToolInvocationResponse
import com.thecyberexpert123.nmaptool.contract.ToolResultDeltaAnalyzer
import com.thecyberexpert123.nmaptool.contract.ToolResultParser
import com.thecyberexpert123.nmaptool.contract.ToolResultSummary
import com.thecyberexpert123.nmaptool.contract.ToolType
import com.thecyberexpert123.nmaptool.contract.ValidationIssue
import com.thecyberexpert123.nmaptool.contract.ValidationResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import java.net.URI
import java.security.MessageDigest
import java.util.UUID

private const val MAX_TEXT_SNAPSHOT = 120_000

data class EditableScanProfile(
    val id: String? = null,
    val name: String = "",
    val tool: ToolType = ToolType.NMAP,
    val executionPreference: ExecutionPreference = ExecutionPreference.AUTO,
    val rawTargets: String = "",
    val rawArguments: String = "",
    val notes: String = "",
)

data class ScanProfileSummary(
    val id: String,
    val name: String,
    val tool: ToolType,
    val executionPreference: ExecutionPreference,
    val targetSummary: String,
    val argumentsPreview: String,
    val updatedAtEpochMillis: Long,
    val scheduleEnabled: Boolean,
    val scheduleRepeatMinutes: Long?,
    val lastRunStatus: RunStatus?,
    val lastRunRoute: ExecutionRoute?,
    val lastRunStartedAtEpochMillis: Long?,
)

data class AutomationScheduleSummary(
    val profileId: String,
    val profileName: String,
    val repeatMinutes: Long,
    val requireUnmeteredNetwork: Boolean,
    val enabled: Boolean,
    val lastRunStatus: RunStatus?,
    val lastRunStartedAtEpochMillis: Long?,
)

enum class RunChangeKind {
    BASELINE,
    UNCHANGED,
    CHANGED,
}

data class ScanRunSummary(
    val id: String,
    val profileId: String?,
    val profileName: String,
    val tool: ToolType,
    val route: ExecutionRoute,
    val status: RunStatus,
    val trigger: RunTrigger,
    val commandPreview: String,
    val exitCode: Int?,
    val stdout: String,
    val stderr: String,
    val message: String,
    val startedAtEpochMillis: Long,
    val finishedAtEpochMillis: Long,
    val stdoutTruncated: Boolean,
    val stderrTruncated: Boolean,
    val nmapXmlOutputTruncated: Boolean,
    val requestId: String?,
    val executorLabel: String?,
    val changeKind: RunChangeKind,
    val changeSummary: String,
    val parsedSummary: ToolResultSummary,
    val newOpenPorts: List<PortFinding>,
    val closedPorts: List<PortFinding>,
) {
    val durationMillis: Long
        get() = (finishedAtEpochMillis - startedAtEpochMillis).coerceAtLeast(0L)
}

class DefaultScanRepository(
    private val profileDao: ScanProfileDao,
    private val scheduleDao: AutomationScheduleDao,
    private val runDao: ScanRunDao,
    private val remoteSettingsStore: RemoteSettingsStore,
    private val remoteExecutorClient: RemoteExecutorClient,
    private val localToolExecutor: LocalToolExecutor,
) {
    fun observeProfiles(): Flow<List<ScanProfileSummary>> =
        combine(
            profileDao.observeAll(),
            scheduleDao.observeAll(),
            runDao.observeRecent(),
        ) { profiles, schedules, runs ->
            val schedulesByProfileId = schedules.associateBy { it.profileId }
            val latestRunsByProfileId = runs
                .filter { it.profileId != null }
                .groupBy { it.profileId!! }
                .mapValues { (_, groupedRuns) -> groupedRuns.maxByOrNull { it.startedAtEpochMillis } }
            profiles.map { entity ->
                val latestRun = latestRunsByProfileId[entity.id]
                val schedule = schedulesByProfileId[entity.id]
                ScanProfileSummary(
                    id = entity.id,
                    name = entity.name,
                    tool = ToolType.valueOf(entity.toolType),
                    executionPreference = ExecutionPreference.valueOf(entity.executionPreference),
                    targetSummary = entity.rawTargets.lineSequence().firstOrNull()?.trim().orEmpty().ifBlank { entity.rawTargets },
                    argumentsPreview = entity.rawArguments,
                    updatedAtEpochMillis = entity.updatedAtEpochMillis,
                    scheduleEnabled = schedule?.enabled == true,
                    scheduleRepeatMinutes = schedule?.repeatMinutes,
                    lastRunStatus = latestRun?.status?.let(RunStatus::valueOf),
                    lastRunRoute = latestRun?.route?.let(ExecutionRoute::valueOf),
                    lastRunStartedAtEpochMillis = latestRun?.startedAtEpochMillis,
                )
            }
        }

    fun observeSchedules(): Flow<List<AutomationScheduleSummary>> =
        combine(
            scheduleDao.observeAll(),
            profileDao.observeAll(),
            runDao.observeRecent(),
        ) { schedules, profiles, runs ->
            val profilesById = profiles.associateBy { it.id }
            val latestRunsByProfileId = runs
                .filter { it.profileId != null }
                .groupBy { it.profileId!! }
                .mapValues { (_, groupedRuns) -> groupedRuns.maxByOrNull { it.startedAtEpochMillis } }
            schedules.mapNotNull { schedule ->
                val profile = profilesById[schedule.profileId] ?: return@mapNotNull null
                val latestRun = latestRunsByProfileId[schedule.profileId]
                AutomationScheduleSummary(
                    profileId = schedule.profileId,
                    profileName = profile.name,
                    repeatMinutes = schedule.repeatMinutes,
                    requireUnmeteredNetwork = schedule.requireUnmeteredNetwork,
                    enabled = schedule.enabled,
                    lastRunStatus = latestRun?.status?.let(RunStatus::valueOf),
                    lastRunStartedAtEpochMillis = latestRun?.startedAtEpochMillis,
                )
            }
        }

    fun observeRuns(): Flow<List<ScanRunSummary>> =
        runDao.observeRecent().map { runs ->
            val parsedRuns = runs.map { entity ->
                val tool = ToolType.valueOf(entity.toolType)
                val status = RunStatus.valueOf(entity.status)
                ParsedRunSnapshot(
                    entity = entity,
                    tool = tool,
                    status = status,
                    parsedSummary = ToolResultParser.parse(
                        tool = tool,
                        status = status,
                        exitCode = entity.exitCode,
                        stdout = entity.stdout,
                        stderr = entity.stderr,
                        nmapXmlOutput = entity.nmapXmlOutput,
                        stdoutTruncated = entity.stdoutTruncated,
                        stderrTruncated = entity.stderrTruncated,
                        nmapXmlOutputTruncated = entity.nmapXmlOutputTruncated,
                    ),
                )
            }
            val changeByRunId = buildRunChangeMap(parsedRuns)
            parsedRuns.map { parsedRun ->
                val entity = parsedRun.entity
                val change = changeByRunId.getValue(entity.id)
                ScanRunSummary(
                    id = entity.id,
                    profileId = entity.profileId,
                    profileName = entity.profileName,
                    tool = parsedRun.tool,
                    route = ExecutionRoute.valueOf(entity.route),
                    status = parsedRun.status,
                    trigger = RunTrigger.valueOf(entity.triggerSource),
                    commandPreview = entity.commandPreview,
                    exitCode = entity.exitCode,
                    stdout = entity.stdout,
                    stderr = entity.stderr,
                    message = entity.message,
                    startedAtEpochMillis = entity.startedAtEpochMillis,
                    finishedAtEpochMillis = entity.finishedAtEpochMillis,
                    stdoutTruncated = entity.stdoutTruncated,
                    stderrTruncated = entity.stderrTruncated,
                    nmapXmlOutputTruncated = entity.nmapXmlOutputTruncated,
                    requestId = entity.requestId,
                    executorLabel = entity.executorLabel,
                    changeKind = change.kind,
                    changeSummary = change.summary,
                    parsedSummary = parsedRun.parsedSummary,
                    newOpenPorts = change.newOpenPorts,
                    closedPorts = change.closedPorts,
                )
            }
        }

    suspend fun loadEditableProfile(profileId: String): EditableScanProfile? {
        val profile = profileDao.getById(profileId) ?: return null
        return EditableScanProfile(
            id = profile.id,
            name = profile.name,
            tool = ToolType.valueOf(profile.toolType),
            executionPreference = ExecutionPreference.valueOf(profile.executionPreference),
            rawTargets = profile.rawTargets,
            rawArguments = profile.rawArguments,
            notes = profile.notes,
        )
    }

    suspend fun loadSchedule(profileId: String): AutomationScheduleEntity? = scheduleDao.getByProfileId(profileId)

    suspend fun saveProfile(profile: EditableScanProfile): ValidationResult<String> {
        val validation = InvocationFactory.fromDraft(
            profileName = profile.name,
            tool = profile.tool,
            executionPreference = profile.executionPreference,
            rawTargets = profile.rawTargets,
            rawArguments = profile.rawArguments,
            notes = profile.notes,
            requestedBy = RunTrigger.MANUAL,
        )
        if (!validation.isValid) {
            return ValidationResult.failure(validation.issues)
        }

        val now = System.currentTimeMillis()
        val id = profile.id ?: UUID.randomUUID().toString()
        val existing = profile.id?.let(profileDao::getById)
        profileDao.upsert(
            ScanProfileEntity(
                id = id,
                name = profile.name.trim(),
                toolType = profile.tool.name,
                executionPreference = profile.executionPreference.name,
                rawTargets = profile.rawTargets.trim(),
                rawArguments = profile.rawArguments.trim(),
                notes = profile.notes.trim(),
                createdAtEpochMillis = existing?.createdAtEpochMillis ?: now,
                updatedAtEpochMillis = now,
            ),
        )
        return ValidationResult.success(id)
    }

    fun readRemoteSettings(): RemoteEndpointSettings = remoteSettingsStore.read()

    fun readLocalCapabilities(): AndroidLocalCapabilities = localToolExecutor.capabilityProfile()

    fun saveRemoteSettings(settings: RemoteEndpointSettings): ValidationResult<Unit> {
        val normalizedUrl = settings.baseUrl.trim()
        if (normalizedUrl.isNotBlank()) {
            val issues = validateRemoteEndpoint(normalizedUrl)
            if (issues.isNotEmpty()) {
                return ValidationResult.failure(issues)
            }
        }
        remoteSettingsStore.save(settings.copy(baseUrl = normalizedUrl))
        return ValidationResult.success(Unit)
    }

    suspend fun fetchRemoteCapabilities(settings: RemoteEndpointSettings = remoteSettingsStore.read()): Result<RemoteCapabilitiesResponse> {
        if (settings.baseUrl.isBlank()) {
            return Result.failure(IllegalStateException("Set a remote executor base URL before requesting capabilities."))
        }
        return remoteExecutorClient.fetchCapabilities(settings)
    }

    suspend fun executeProfile(profileId: String, trigger: RunTrigger): ToolInvocationResponse {
        val profile = profileDao.getById(profileId)
            ?: return ToolInvocationResponse(
                route = ExecutionRoute.BLOCKED,
                status = RunStatus.BLOCKED,
                commandPreview = "",
                stdout = "",
                stderr = "Profile not found.",
                startedAtEpochMillis = System.currentTimeMillis(),
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Profile not found.",
            )

        val tool = ToolType.valueOf(profile.toolType)
        val validation = InvocationFactory.fromDraft(
            profileName = profile.name,
            tool = tool,
            executionPreference = ExecutionPreference.valueOf(profile.executionPreference),
            rawTargets = profile.rawTargets,
            rawArguments = profile.rawArguments,
            notes = profile.notes,
            requestedBy = trigger,
        )
        val response = if (!validation.isValid) {
            val message = validation.issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }
            ToolInvocationResponse(
                route = ExecutionRoute.BLOCKED,
                status = RunStatus.BLOCKED,
                commandPreview = CommandPreview.render(tool, emptyList(), emptyList()),
                stdout = "",
                stderr = message,
                startedAtEpochMillis = System.currentTimeMillis(),
                finishedAtEpochMillis = System.currentTimeMillis(),
                message = "Profile validation failed.",
            )
        } else {
            val request = validation.value!!.request
            val localDecision = localToolExecutor.inspect(request)
            val remoteSettings = remoteSettingsStore.read()
            when (request.executionPreference) {
                ExecutionPreference.LOCAL_ONLY -> localToolExecutor.execute(request)
                ExecutionPreference.REMOTE_ONLY -> {
                    if (remoteSettings.baseUrl.isBlank()) {
                        buildFailureResponse(
                            route = ExecutionRoute.BLOCKED,
                            commandPreview = validation.value.commandPreview,
                            message = "Remote execution was requested, but no remote base URL is configured.",
                        )
                    } else {
                        remoteExecutorClient.execute(remoteSettings, request)
                    }
                }

                ExecutionPreference.AUTO -> {
                    if (localDecision.canExecute) {
                        localToolExecutor.execute(request)
                    } else if (remoteSettings.baseUrl.isNotBlank()) {
                        remoteExecutorClient.execute(remoteSettings, request)
                    } else {
                        buildFailureResponse(
                            route = ExecutionRoute.BLOCKED,
                            commandPreview = validation.value.commandPreview,
                            message = localDecision.reason,
                        )
                    }
                }
            }
        }

        return persistAndReturn(
            response = response,
            profileId = profile.id,
            profileName = profile.name,
            tool = tool,
            trigger = trigger,
        )
    }

    private suspend fun persistAndReturn(
        response: ToolInvocationResponse,
        profileId: String?,
        profileName: String,
        tool: ToolType,
        trigger: RunTrigger,
    ): ToolInvocationResponse {
        runDao.upsert(
            ScanRunEntity(
                id = UUID.randomUUID().toString(),
                profileId = profileId,
                profileName = profileName,
                toolType = tool.name,
                route = response.route.name,
                status = response.status.name,
                triggerSource = trigger.name,
                commandPreview = response.commandPreview,
                exitCode = response.exitCode,
                stdout = response.stdout.take(MAX_TEXT_SNAPSHOT),
                stderr = response.stderr.take(MAX_TEXT_SNAPSHOT),
                message = response.message.take(4_000),
                startedAtEpochMillis = response.startedAtEpochMillis,
                finishedAtEpochMillis = response.finishedAtEpochMillis,
                nmapXmlOutput = response.nmapXmlOutput?.take(MAX_TEXT_SNAPSHOT),
                stdoutTruncated = response.stdoutTruncated,
                stderrTruncated = response.stderrTruncated,
                nmapXmlOutputTruncated = response.nmapXmlOutputTruncated,
                requestId = response.requestId?.take(200),
                executorLabel = response.executorLabel?.take(200),
            ),
        )
        return response
    }

    private fun buildFailureResponse(
        route: ExecutionRoute,
        commandPreview: String,
        message: String,
    ): ToolInvocationResponse = ToolInvocationResponse(
        route = route,
        status = RunStatus.BLOCKED,
        commandPreview = commandPreview,
        stdout = "",
        stderr = message,
        startedAtEpochMillis = System.currentTimeMillis(),
        finishedAtEpochMillis = System.currentTimeMillis(),
        message = message,
    )

    private fun validateRemoteEndpoint(baseUrl: String): List<ValidationIssue> {
        val issues = mutableListOf<ValidationIssue>()
        runCatching {
            val uri = URI(baseUrl)
            require(uri.scheme == "http" || uri.scheme == "https")
            require(!uri.host.isNullOrBlank())
        }.onFailure {
            issues += ValidationIssue(
                field = "baseUrl",
                message = "Remote executor URL must use http/https and include a host.",
            )
        }
        return issues
    }

    private fun buildRunChangeMap(runs: List<ParsedRunSnapshot>): Map<String, RunChangeSummary> {
        val changes = mutableMapOf<String, RunChangeSummary>()
        runs.groupBy { snapshot -> snapshot.entity.profileId ?: "${snapshot.entity.toolType}:${snapshot.entity.profileName}" }
            .values
            .forEach { profileRuns ->
                val ordered = profileRuns.sortedBy { it.entity.startedAtEpochMillis }
                ordered.forEachIndexed { index, current ->
                    val previous = ordered.getOrNull(index - 1)
                    changes[current.entity.id] = compareRuns(previous, current)
                }
            }
        return changes
    }

    private fun compareRuns(previous: ParsedRunSnapshot?, current: ParsedRunSnapshot): RunChangeSummary {
        if (previous == null) {
            return RunChangeSummary(
                kind = RunChangeKind.BASELINE,
                summary = "First recorded run for this profile.",
            )
        }

        val deltas = mutableListOf<String>()
        if (previous.status != current.status) {
            deltas += "status ${previous.status} → ${current.status}"
        }
        if (previous.entity.route != current.entity.route) {
            deltas += "route ${previous.entity.route} → ${current.entity.route}"
        }
        if (previous.entity.exitCode != current.entity.exitCode) {
            deltas += "exit code ${previous.entity.exitCode ?: "none"} → ${current.entity.exitCode ?: "none"}"
        }
        if (previous.entity.commandPreview != current.entity.commandPreview) {
            deltas += "command arguments changed"
        }
        if (
            fingerprint(previous.entity.stdout) != fingerprint(current.entity.stdout) ||
            fingerprint(previous.entity.stderr) != fingerprint(current.entity.stderr) ||
            fingerprint(previous.entity.nmapXmlOutput.orEmpty()) != fingerprint(current.entity.nmapXmlOutput.orEmpty()) ||
            previous.entity.stdoutTruncated != current.entity.stdoutTruncated ||
            previous.entity.stderrTruncated != current.entity.stderrTruncated ||
            previous.entity.nmapXmlOutputTruncated != current.entity.nmapXmlOutputTruncated
        ) {
            deltas += "captured output changed"
        }

        val parsedDelta = ToolResultDeltaAnalyzer.compare(
            tool = current.tool,
            previous = previous.parsedSummary,
            current = current.parsedSummary,
        )
        val parsedDeltaIsInformative = parsedDelta.newOpenPorts.isNotEmpty() || parsedDelta.closedPorts.isNotEmpty()
        if (parsedDeltaIsInformative) {
            deltas += parsedDelta.summary
        }

        return if (deltas.isEmpty()) {
            RunChangeSummary(
                kind = RunChangeKind.UNCHANGED,
                summary = "No meaningful delta from the previous recorded run.",
                newOpenPorts = parsedDelta.newOpenPorts,
                closedPorts = parsedDelta.closedPorts,
            )
        } else {
            RunChangeSummary(
                kind = RunChangeKind.CHANGED,
                summary = deltas.joinToString(separator = "; "),
                newOpenPorts = parsedDelta.newOpenPorts,
                closedPorts = parsedDelta.closedPorts,
            )
        }
    }

    private fun fingerprint(value: String): String {
        if (value.isBlank()) {
            return ""
        }
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(value.toByteArray()).joinToString(separator = "") { byte ->
            "%02x".format(byte)
        }
    }

    private data class ParsedRunSnapshot(
        val entity: ScanRunEntity,
        val tool: ToolType,
        val status: RunStatus,
        val parsedSummary: ToolResultSummary,
    )

    private data class RunChangeSummary(
        val kind: RunChangeKind,
        val summary: String,
        val newOpenPorts: List<PortFinding> = emptyList(),
        val closedPorts: List<PortFinding> = emptyList(),
    )
}
