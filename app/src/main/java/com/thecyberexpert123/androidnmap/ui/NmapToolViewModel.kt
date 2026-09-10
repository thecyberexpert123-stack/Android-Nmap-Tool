package com.thecyberexpert123.androidnmap.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.thecyberexpert123.androidnmap.data.AutomationScheduleSummary
import com.thecyberexpert123.androidnmap.data.DefaultScanRepository
import com.thecyberexpert123.androidnmap.data.EditableScanProfile
import com.thecyberexpert123.androidnmap.data.ScanProfileSummary
import com.thecyberexpert123.androidnmap.data.ScanRunSummary
import com.thecyberexpert123.androidnmap.execution.DelegatedExecutorEndpointRecord
import com.thecyberexpert123.androidnmap.execution.DelegatedExecutorResolver
import com.thecyberexpert123.androidnmap.settings.DelegatedExecutorSettingsBundle
import com.thecyberexpert123.androidnmap.settings.DelegatedExecutorSlot
import com.thecyberexpert123.androidnmap.settings.RemoteEndpointSettings
import com.thecyberexpert123.androidnmap.work.AutomationScheduler
import com.thecyberexpert123.nmaptool.contract.AndroidLocalCapabilities
import com.thecyberexpert123.nmaptool.contract.ArgumentTokenizer
import com.thecyberexpert123.nmaptool.contract.CommandPreview
import com.thecyberexpert123.nmaptool.contract.CommandSafetyPolicy
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidance
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidanceAdvisor
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidanceStatus
import com.thecyberexpert123.nmaptool.contract.ExecutionPreference
import com.thecyberexpert123.nmaptool.contract.ExecutorCapabilityProfile
import com.thecyberexpert123.nmaptool.contract.ExecutorNodeKind
import com.thecyberexpert123.nmaptool.contract.NmapTimingTemplate
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.RunTrigger
import com.thecyberexpert123.nmaptool.contract.ScanPreset
import com.thecyberexpert123.nmaptool.contract.StructuredNmapArgumentComposer
import com.thecyberexpert123.nmaptool.contract.StructuredNmapOptions
import com.thecyberexpert123.nmaptool.contract.TargetParser
import com.thecyberexpert123.nmaptool.contract.ToolType
import com.thecyberexpert123.nmaptool.contract.toExecutorCapabilityProfile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ScanBuilderUiState(
    val id: String? = null,
    val name: String = "",
    val tool: ToolType = ToolType.NMAP,
    val executionPreference: ExecutionPreference = ExecutionPreference.AUTO,
    val rawTargets: String = "",
    val notes: String = "",
    val scheduleEnabled: Boolean = false,
    val scheduleMinutes: String = "60",
    val requireUnmeteredNetwork: Boolean = false,
    val selectedPreset: ScanPreset? = ScanPreset.QUICK_TCP,
    val skipHostDiscovery: Boolean = true,
    val enableServiceDetection: Boolean = false,
    val enableDefaultScripts: Boolean = false,
    val enableOsDetection: Boolean = false,
    val enableTraceroute: Boolean = false,
    val timingTemplate: NmapTimingTemplate = NmapTimingTemplate.AGGRESSIVE,
    val portList: String = "",
    val topPorts: String = "",
    val scriptSelection: String = "",
    val expertArguments: String = "-F",
    val effectiveArguments: String = "",
    val commandPreview: String = "",
    val builderIssues: List<String> = emptyList(),
    val executionGuidance: ExecutionGuidance = ExecutionGuidance(),
    val delegatedExecutorContextLabel: String? = null,
    val delegatedExecutorSelectionReason: String? = null,
    val delegatedLastCheckedAtEpochMillis: Long? = null,
    val delegatedCapabilitiesLoading: Boolean = false,
    val delegatedCapabilitiesStale: Boolean = false,
)

data class RemoteSettingsUiState(
    val baseUrl: String = "",
    val bearerToken: String = "",
    val lanAgentBaseUrl: String = "",
    val lanAgentBearerToken: String = "",
)

data class CapabilityUiState(
    val loading: Boolean = false,
    val capabilities: RemoteCapabilitiesResponse? = null,
    val error: String? = null,
    val lastCheckedAtEpochMillis: Long? = null,
    val stale: Boolean = false,
    val lanAgentLoading: Boolean = false,
    val lanAgentCapabilities: RemoteCapabilitiesResponse? = null,
    val lanAgentError: String? = null,
    val lanAgentLastCheckedAtEpochMillis: Long? = null,
    val lanAgentStale: Boolean = false,
)

data class LocalCapabilityUiState(
    val capabilities: AndroidLocalCapabilities,
    val executorProfile: ExecutorCapabilityProfile,
    val lastCheckedAtEpochMillis: Long,
)

class NmapToolViewModel(
    private val repository: DefaultScanRepository,
    private val automationScheduler: AutomationScheduler,
) : ViewModel() {
    val profiles: StateFlow<List<ScanProfileSummary>> = repository.observeProfiles().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = emptyList(),
    )
    val schedules: StateFlow<List<AutomationScheduleSummary>> = repository.observeSchedules().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = emptyList(),
    )
    val runs: StateFlow<List<ScanRunSummary>> = repository.observeRuns().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = emptyList(),
    )

    private val _remoteSettings = MutableStateFlow(RemoteSettingsUiState())
    val remoteSettings: StateFlow<RemoteSettingsUiState> = _remoteSettings.asStateFlow()

    private val _capabilityState = MutableStateFlow(CapabilityUiState())
    val capabilityState: StateFlow<CapabilityUiState> = _capabilityState.asStateFlow()

    private val _localCapabilityState = MutableStateFlow(
        repository.readLocalCapabilities().let { capabilities ->
            LocalCapabilityUiState(
                capabilities = capabilities,
                executorProfile = capabilities.toExecutorCapabilityProfile(),
                lastCheckedAtEpochMillis = System.currentTimeMillis(),
            )
        },
    )
    val localCapabilityState: StateFlow<LocalCapabilityUiState> = _localCapabilityState.asStateFlow()

    private val _builderState = MutableStateFlow(recalculate(ScanBuilderUiState()))
    val builderState: StateFlow<ScanBuilderUiState> = _builderState.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    init {
        val savedSettings = repository.readDelegatedExecutorSettings()
        val savedSnapshots = repository.readDelegatedCapabilitySnapshots()
        _remoteSettings.value = RemoteSettingsUiState(
            baseUrl = savedSettings.primary.baseUrl,
            bearerToken = savedSettings.primary.bearerToken,
            lanAgentBaseUrl = savedSettings.lanAgent.baseUrl,
            lanAgentBearerToken = savedSettings.lanAgent.bearerToken,
        )
        _capabilityState.value = CapabilityUiState(
            capabilities = savedSnapshots.primary?.capabilities,
            lastCheckedAtEpochMillis = savedSnapshots.primary?.checkedAtEpochMillis,
            lanAgentCapabilities = savedSnapshots.lanAgent?.capabilities,
            lanAgentLastCheckedAtEpochMillis = savedSnapshots.lanAgent?.checkedAtEpochMillis,
        )
        refreshBuilderDerivedState()
    }

    fun consumeMessage() {
        _message.value = null
    }

    fun publishMessage(value: String) {
        _message.value = value
    }

    fun updateName(value: String) = updateBuilder { it.copy(name = value) }

    fun updateTool(value: ToolType) = updateBuilder { state ->
        val preset = state.selectedPreset?.takeIf { it.tool == value }
        if (value == ToolType.NMAP && state.tool != ToolType.NMAP) {
            val inferred = StructuredNmapArgumentComposer.inferFromRawArguments(state.expertArguments)
            state.copy(
                tool = value,
                selectedPreset = preset,
                skipHostDiscovery = inferred.skipHostDiscovery,
                enableServiceDetection = inferred.enableServiceDetection,
                enableDefaultScripts = inferred.enableDefaultScripts,
                enableOsDetection = inferred.enableOsDetection,
                enableTraceroute = inferred.enableTraceroute,
                timingTemplate = inferred.timingTemplate,
                portList = inferred.portList,
                topPorts = inferred.topPorts,
                scriptSelection = inferred.scriptSelection,
                expertArguments = inferred.extraArguments,
            )
        } else {
            state.copy(tool = value, selectedPreset = preset)
        }
    }

    fun updateExecutionPreference(value: ExecutionPreference) = updateBuilder { it.copy(executionPreference = value) }

    fun updateTargets(value: String) = updateBuilder { it.copy(rawTargets = value) }

    fun updateExpertArguments(value: String) = updateBuilder { it.copy(expertArguments = value, selectedPreset = null) }

    fun updateNotes(value: String) = updateBuilder { it.copy(notes = value) }

    fun updateScheduleEnabled(value: Boolean) = updateBuilder { it.copy(scheduleEnabled = value) }

    fun updateScheduleMinutes(value: String) = updateBuilder { it.copy(scheduleMinutes = value) }

    fun updateRequireUnmeteredNetwork(value: Boolean) = updateBuilder { it.copy(requireUnmeteredNetwork = value) }

    fun updateSkipHostDiscovery(value: Boolean) = updateBuilder { it.copy(skipHostDiscovery = value, selectedPreset = null) }

    fun updateServiceDetection(value: Boolean) = updateBuilder { it.copy(enableServiceDetection = value, selectedPreset = null) }

    fun updateDefaultScripts(value: Boolean) = updateBuilder { it.copy(enableDefaultScripts = value, selectedPreset = null) }

    fun updateOsDetection(value: Boolean) = updateBuilder { it.copy(enableOsDetection = value, selectedPreset = null) }

    fun updateTraceroute(value: Boolean) = updateBuilder { it.copy(enableTraceroute = value, selectedPreset = null) }

    fun updateTimingTemplate(value: NmapTimingTemplate) = updateBuilder { it.copy(timingTemplate = value, selectedPreset = null) }

    fun updatePortList(value: String) = updateBuilder { it.copy(portList = value, selectedPreset = null) }

    fun updateTopPorts(value: String) = updateBuilder { it.copy(topPorts = value, selectedPreset = null) }

    fun updateScriptSelection(value: String) = updateBuilder { it.copy(scriptSelection = value, selectedPreset = null) }

    fun applyPreset(preset: ScanPreset) = updateBuilder { state ->
        if (preset.tool == ToolType.NMAP) {
            val inferred = StructuredNmapArgumentComposer.inferFromRawArguments(
                CommandPreview.renderArguments(preset.suggestedArguments),
            )
            state.copy(
                tool = ToolType.NMAP,
                selectedPreset = preset,
                skipHostDiscovery = inferred.skipHostDiscovery,
                enableServiceDetection = inferred.enableServiceDetection,
                enableDefaultScripts = inferred.enableDefaultScripts,
                enableOsDetection = inferred.enableOsDetection,
                enableTraceroute = inferred.enableTraceroute,
                timingTemplate = inferred.timingTemplate,
                portList = inferred.portList,
                topPorts = inferred.topPorts,
                scriptSelection = inferred.scriptSelection,
                expertArguments = inferred.extraArguments,
            )
        } else {
            state.copy(
                tool = preset.tool,
                selectedPreset = preset,
                expertArguments = CommandPreview.renderArguments(preset.suggestedArguments),
            )
        }
    }

    fun clearDraft() {
        _builderState.value = recalculate(ScanBuilderUiState())
    }

    fun loadProfile(profileId: String) {
        viewModelScope.launch {
            val profile = repository.loadEditableProfile(profileId)
            val schedule = repository.loadSchedule(profileId)
            if (profile == null) {
                _message.value = "Profile could not be loaded."
                return@launch
            }

            val baseState = ScanBuilderUiState(
                id = profile.id,
                name = profile.name,
                tool = profile.tool,
                executionPreference = profile.executionPreference,
                rawTargets = profile.rawTargets,
                notes = profile.notes,
                scheduleEnabled = schedule?.enabled == true,
                scheduleMinutes = schedule?.repeatMinutes?.toString() ?: "60",
                requireUnmeteredNetwork = schedule?.requireUnmeteredNetwork == true,
                selectedPreset = null,
            )

            _builderState.value = if (profile.tool == ToolType.NMAP) {
                val inferred = StructuredNmapArgumentComposer.inferFromRawArguments(profile.rawArguments)
                recalculate(
                    baseState.copy(
                        skipHostDiscovery = inferred.skipHostDiscovery,
                        enableServiceDetection = inferred.enableServiceDetection,
                        enableDefaultScripts = inferred.enableDefaultScripts,
                        enableOsDetection = inferred.enableOsDetection,
                        enableTraceroute = inferred.enableTraceroute,
                        timingTemplate = inferred.timingTemplate,
                        portList = inferred.portList,
                        topPorts = inferred.topPorts,
                        scriptSelection = inferred.scriptSelection,
                        expertArguments = inferred.extraArguments,
                        selectedPreset = ScanPreset.entries.firstOrNull {
                            it.tool == profile.tool &&
                                CommandPreview.renderArguments(it.suggestedArguments) == profile.rawArguments.trim()
                        },
                    ),
                )
            } else {
                recalculate(
                    baseState.copy(
                        expertArguments = profile.rawArguments,
                        selectedPreset = ScanPreset.entries.firstOrNull {
                            it.tool == profile.tool &&
                                CommandPreview.renderArguments(it.suggestedArguments) == profile.rawArguments.trim()
                        },
                    ),
                )
            }
            _message.value = "Loaded profile into the builder."
        }
    }

    fun saveProfile() {
        viewModelScope.launch {
            persistCurrentDraft(showSuccessMessage = true)
        }
    }

    fun runCurrentDraft() {
        viewModelScope.launch {
            val profileId = persistCurrentDraft(showSuccessMessage = false) ?: return@launch
            val result = repository.executeProfile(profileId, RunTrigger.MANUAL)
            _message.value = result.message.ifBlank {
                "Manual run completed with status ${result.status.name.lowercase()}."
            }
        }
    }

    fun runExistingProfile(profileId: String) {
        viewModelScope.launch {
            val result = repository.executeProfile(profileId, RunTrigger.MANUAL)
            _message.value = result.message.ifBlank {
                "Profile run completed with status ${result.status.name.lowercase()}."
            }
        }
    }

    fun updateRemoteBaseUrl(value: String) {
        _remoteSettings.update { it.copy(baseUrl = value) }
        markCapabilitiesStale(primary = true, lanAgent = false)
        refreshBuilderDerivedState()
    }

    fun updateRemoteToken(value: String) {
        _remoteSettings.update { it.copy(bearerToken = value) }
        markCapabilitiesStale(primary = true, lanAgent = false)
        refreshBuilderDerivedState()
    }

    fun updateLanAgentBaseUrl(value: String) {
        _remoteSettings.update { it.copy(lanAgentBaseUrl = value) }
        markCapabilitiesStale(primary = false, lanAgent = true)
        refreshBuilderDerivedState()
    }

    fun updateLanAgentToken(value: String) {
        _remoteSettings.update { it.copy(lanAgentBearerToken = value) }
        markCapabilitiesStale(primary = false, lanAgent = true)
        refreshBuilderDerivedState()
    }

    fun saveRemoteSettings() {
        viewModelScope.launch {
            val settings = currentDelegatedSettingsBundle()
            val result = repository.saveDelegatedExecutorSettings(settings)
            if (result.isValid) {
                val capabilityRefreshErrors = refreshCapabilitiesForBundle(settings)
                _message.value = if (capabilityRefreshErrors.isNotEmpty()) {
                    "Delegated executor settings saved securely on-device, but some capability refreshes failed."
                } else {
                    "Delegated executor settings saved securely on-device."
                }
            } else {
                _message.value = result.issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }
            }
        }
    }

    fun refreshCapabilities() {
        viewModelScope.launch {
            refreshCapabilitiesForBundle(
                currentDelegatedSettingsBundle(),
                publishMessageOnFailure = true,
            )
        }
    }

    fun refreshLocalCapabilities() {
        val refreshed = repository.readLocalCapabilities()
        _localCapabilityState.value = LocalCapabilityUiState(
            capabilities = refreshed,
            executorProfile = refreshed.toExecutorCapabilityProfile(),
            lastCheckedAtEpochMillis = System.currentTimeMillis(),
        )
        refreshBuilderDerivedState()
        _message.value = "Refreshed Android-local capability snapshot."
    }

    private suspend fun refreshCapabilitiesForBundle(
        settings: DelegatedExecutorSettingsBundle,
        publishMessageOnFailure: Boolean = false,
    ): List<String> {
        val errors = buildList {
            refreshCapabilitiesForEndpoint(
                settings = settings.primary,
                lane = DelegatedCapabilityLane.PRIMARY,
                publishMessageOnFailure = publishMessageOnFailure,
            )?.let(::add)
            refreshCapabilitiesForEndpoint(
                settings = settings.lanAgent,
                lane = DelegatedCapabilityLane.LAN_AGENT,
                publishMessageOnFailure = publishMessageOnFailure,
            )?.let(::add)
        }
        refreshBuilderDerivedState()
        return errors
    }

    private suspend fun refreshCapabilitiesForEndpoint(
        settings: RemoteEndpointSettings,
        lane: DelegatedCapabilityLane,
        publishMessageOnFailure: Boolean = false,
    ): String? {
        if (settings.baseUrl.isBlank()) {
            clearCapabilityLane(lane)
            return null
        }

        val refreshStartedAt = System.currentTimeMillis()
        _capabilityState.update { current ->
            when (lane) {
                DelegatedCapabilityLane.PRIMARY -> current.copy(loading = true, error = null)
                DelegatedCapabilityLane.LAN_AGENT -> current.copy(lanAgentLoading = true, lanAgentError = null)
            }
        }

        var failureMessage: String? = null
        repository.fetchRemoteCapabilities(settings)
            .onSuccess { capabilities ->
                if (savedSettingsMatch(lane, settings)) {
                    repository.cacheDelegatedCapabilitySnapshot(
                        slot = lane.toDelegatedExecutorSlot(),
                        capabilities = capabilities,
                        checkedAtEpochMillis = refreshStartedAt,
                    )
                }
                _capabilityState.update { current ->
                    when (lane) {
                        DelegatedCapabilityLane.PRIMARY -> current.copy(
                            loading = false,
                            capabilities = capabilities,
                            error = null,
                            lastCheckedAtEpochMillis = refreshStartedAt,
                            stale = false,
                        )
                        DelegatedCapabilityLane.LAN_AGENT -> current.copy(
                            lanAgentLoading = false,
                            lanAgentCapabilities = capabilities,
                            lanAgentError = null,
                            lanAgentLastCheckedAtEpochMillis = refreshStartedAt,
                            lanAgentStale = false,
                        )
                    }
                }
            }
            .onFailure { error ->
                failureMessage = error.message ?: "Failed to load delegated executor capabilities."
                _capabilityState.update { current ->
                    when (lane) {
                        DelegatedCapabilityLane.PRIMARY -> current.copy(
                            loading = false,
                            capabilities = null,
                            error = failureMessage,
                            lastCheckedAtEpochMillis = refreshStartedAt,
                            stale = false,
                        )
                        DelegatedCapabilityLane.LAN_AGENT -> current.copy(
                            lanAgentLoading = false,
                            lanAgentCapabilities = null,
                            lanAgentError = failureMessage,
                            lanAgentLastCheckedAtEpochMillis = refreshStartedAt,
                            lanAgentStale = false,
                        )
                    }
                }
                if (publishMessageOnFailure) {
                    _message.value = failureMessage
                }
            }
        return failureMessage
    }

    private suspend fun persistCurrentDraft(showSuccessMessage: Boolean): String? {
        val currentState = builderState.value
        if (currentState.builderIssues.isNotEmpty()) {
            _message.value = currentState.builderIssues.joinToString(separator = "\n")
            return null
        }

        val scheduleMinutes = currentState.scheduleMinutes.toLongOrNull()
        if (currentState.scheduleEnabled && scheduleMinutes == null) {
            _message.value = "Schedule interval must be a whole number of minutes."
            return null
        }
        if (currentState.scheduleEnabled && scheduleMinutes != null && scheduleMinutes < 15L) {
            _message.value = "Periodic automation must be at least 15 minutes."
            return null
        }

        val draft = EditableScanProfile(
            id = currentState.id,
            name = currentState.name,
            tool = currentState.tool,
            executionPreference = currentState.executionPreference,
            rawTargets = currentState.rawTargets,
            rawArguments = currentState.effectiveArguments,
            notes = currentState.notes,
        )
        val result = repository.saveProfile(draft)
        if (!result.isValid) {
            _message.value = result.issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }
            return null
        }

        val profileId = result.value!!
        automationScheduler.syncSchedule(
            profileId = profileId,
            enabled = currentState.scheduleEnabled,
            repeatMinutes = scheduleMinutes,
            requireUnmeteredNetwork = currentState.requireUnmeteredNetwork,
        )
        _builderState.update { it.copy(id = profileId) }

        if (showSuccessMessage) {
            _message.value = if (currentState.scheduleEnabled) {
                "Profile saved and automation synchronized."
            } else {
                "Profile saved."
            }
        }
        return profileId
    }

    private fun updateBuilder(transform: (ScanBuilderUiState) -> ScanBuilderUiState) {
        _builderState.update { current -> recalculate(transform(current)) }
    }

    private fun refreshBuilderDerivedState() {
        _builderState.update(::recalculate)
    }

    private fun currentDelegatedSettingsBundle(): DelegatedExecutorSettingsBundle =
        DelegatedExecutorSettingsBundle(
            primary = RemoteEndpointSettings(
                baseUrl = remoteSettings.value.baseUrl,
                bearerToken = remoteSettings.value.bearerToken,
            ),
            lanAgent = RemoteEndpointSettings(
                baseUrl = remoteSettings.value.lanAgentBaseUrl,
                bearerToken = remoteSettings.value.lanAgentBearerToken,
            ),
        )

    private fun clearCapabilityLane(lane: DelegatedCapabilityLane) {
        _capabilityState.update { current ->
            when (lane) {
                DelegatedCapabilityLane.PRIMARY -> current.copy(
                    loading = false,
                    capabilities = null,
                    error = null,
                    lastCheckedAtEpochMillis = null,
                    stale = false,
                )
                DelegatedCapabilityLane.LAN_AGENT -> current.copy(
                    lanAgentLoading = false,
                    lanAgentCapabilities = null,
                    lanAgentError = null,
                    lanAgentLastCheckedAtEpochMillis = null,
                    lanAgentStale = false,
                )
            }
        }
    }

    private fun markCapabilitiesStale(primary: Boolean, lanAgent: Boolean) {
        _capabilityState.update { current ->
            current.copy(
                stale = if (primary && (current.capabilities != null || current.error != null || current.lastCheckedAtEpochMillis != null)) true else current.stale,
                lanAgentStale = if (lanAgent && (current.lanAgentCapabilities != null || current.lanAgentError != null || current.lanAgentLastCheckedAtEpochMillis != null)) true else current.lanAgentStale,
            )
        }
    }

    private fun delegatedExecutorRecords(): List<DelegatedExecutorEndpointRecord> = listOf(
        DelegatedExecutorEndpointRecord(
            slot = DelegatedExecutorSlot.PRIMARY,
            label = "Primary delegated executor",
            settings = RemoteEndpointSettings(
                baseUrl = remoteSettings.value.baseUrl,
                bearerToken = remoteSettings.value.bearerToken,
            ),
            fallbackKind = ExecutorNodeKind.REMOTE_NMAP,
            capabilities = capabilityState.value.capabilities,
            capabilitiesCheckedAtEpochMillis = capabilityState.value.lastCheckedAtEpochMillis,
            capabilitiesStale = capabilityState.value.stale,
        ),
        DelegatedExecutorEndpointRecord(
            slot = DelegatedExecutorSlot.LAN_AGENT,
            label = "LAN agent",
            settings = RemoteEndpointSettings(
                baseUrl = remoteSettings.value.lanAgentBaseUrl,
                bearerToken = remoteSettings.value.lanAgentBearerToken,
            ),
            fallbackKind = ExecutorNodeKind.LAN_AGENT,
            capabilities = capabilityState.value.lanAgentCapabilities,
            capabilitiesCheckedAtEpochMillis = capabilityState.value.lanAgentLastCheckedAtEpochMillis,
            capabilitiesStale = capabilityState.value.lanAgentStale,
        ),
    )

    private fun savedSettingsMatch(
        lane: DelegatedCapabilityLane,
        settings: RemoteEndpointSettings,
    ): Boolean {
        val saved = repository.readDelegatedExecutorSettings()
        val currentSaved = when (lane) {
            DelegatedCapabilityLane.PRIMARY -> saved.primary
            DelegatedCapabilityLane.LAN_AGENT -> saved.lanAgent
        }
        return currentSaved.baseUrl.trim() == settings.baseUrl.trim() &&
            currentSaved.bearerToken.trim() == settings.bearerToken.trim()
    }

    private fun DelegatedCapabilityLane.toDelegatedExecutorSlot(): DelegatedExecutorSlot = when (this) {
        DelegatedCapabilityLane.PRIMARY -> DelegatedExecutorSlot.PRIMARY
        DelegatedCapabilityLane.LAN_AGENT -> DelegatedExecutorSlot.LAN_AGENT
    }

    private fun applyDelegatedCompatibilityMessage(
        guidance: ExecutionGuidance,
        compatibilityMessage: String?,
        executionPreference: ExecutionPreference,
    ): ExecutionGuidance {
        if (compatibilityMessage.isNullOrBlank()) {
            return guidance
        }
        return when {
            guidance.status == ExecutionGuidanceStatus.BLOCKED || executionPreference == ExecutionPreference.REMOTE_ONLY -> guidance.copy(
                status = ExecutionGuidanceStatus.BLOCKED,
                blockers = (guidance.blockers + compatibilityMessage).distinct(),
            )

            else -> guidance.copy(
                warnings = (guidance.warnings + compatibilityMessage).distinct(),
                status = ExecutionGuidanceStatus.CAUTION,
            )
        }
    }

    private fun recalculate(state: ScanBuilderUiState): ScanBuilderUiState {
        val issues = mutableListOf<String>()
        val effectiveArguments = when (state.tool) {
            ToolType.NMAP -> {
                val result = StructuredNmapArgumentComposer.build(
                    StructuredNmapOptions(
                        skipHostDiscovery = state.skipHostDiscovery,
                        enableServiceDetection = state.enableServiceDetection,
                        enableDefaultScripts = state.enableDefaultScripts,
                        enableOsDetection = state.enableOsDetection,
                        enableTraceroute = state.enableTraceroute,
                        timingTemplate = state.timingTemplate,
                        portList = state.portList,
                        topPorts = state.topPorts,
                        scriptSelection = state.scriptSelection,
                        extraArguments = state.expertArguments,
                    ),
                )
                issues += result.issues.map { "${it.field}: ${it.message}" }
                result.value.orEmpty()
            }

            else -> {
                val tokenResult = tokenizeAndValidate(state.tool, state.expertArguments)
                issues += tokenResult.issues
                CommandPreview.renderArguments(tokenResult.arguments)
            }
        }

        val effectiveArgumentTokens = runCatching { ArgumentTokenizer.tokenize(effectiveArguments) }.getOrDefault(emptyList())
        val targets = TargetParser.parse(state.rawTargets)
        val commandPreview = if (effectiveArguments.isBlank()) {
            state.tool.binaryName + state.rawTargets.trim().let { suffix -> if (suffix.isBlank()) "" else " $suffix" }
        } else {
            runCatching {
                CommandPreview.render(
                    tool = state.tool,
                    arguments = effectiveArgumentTokens,
                    targets = targets,
                )
            }.getOrDefault(
                listOf(state.tool.binaryName, effectiveArguments, state.rawTargets.trim())
                    .filter { it.isNotBlank() }
                    .joinToString(" "),
            )
        }
        val capabilitySnapshot = capabilityState.value
        val localCapabilitySnapshot = localCapabilityState.value.capabilities
        val delegatedRecords = delegatedExecutorRecords()
        val delegatedSelection = DelegatedExecutorResolver.select(
            targets = targets,
            records = delegatedRecords,
        )
        val delegatedCompatibilityMessage = DelegatedExecutorResolver.incompatibilityMessage(
            targets = targets,
            records = delegatedRecords,
        )
        val baseGuidance = ExecutionGuidanceAdvisor.analyze(
            tool = state.tool,
            targets = targets,
            executionPreference = state.executionPreference,
            arguments = effectiveArgumentTokens,
            remoteConfigured = delegatedSelection != null,
            remoteCapabilities = delegatedSelection?.capabilities,
            remoteCapabilitiesStale = delegatedSelection?.capabilitiesStale ?: false,
            localCapabilities = localCapabilitySnapshot,
            scheduleEnabled = state.scheduleEnabled,
        )
        val compatibilityAwareGuidance = applyDelegatedCompatibilityMessage(
            guidance = baseGuidance,
            compatibilityMessage = delegatedCompatibilityMessage,
            executionPreference = state.executionPreference,
        )
        val executionGuidance = if (issues.isNotEmpty()) {
            compatibilityAwareGuidance.copy(
                status = ExecutionGuidanceStatus.BLOCKED,
                summary = "Resolve builder issues before execution readiness can be trusted.",
                blockers = (listOf("Resolve the builder issues shown below.") + compatibilityAwareGuidance.blockers).distinct(),
            )
        } else {
            compatibilityAwareGuidance
        }
        val delegatedLoading = when (delegatedSelection?.slot) {
            DelegatedExecutorSlot.PRIMARY -> capabilitySnapshot.loading
            DelegatedExecutorSlot.LAN_AGENT -> capabilitySnapshot.lanAgentLoading
            null -> capabilitySnapshot.loading || capabilitySnapshot.lanAgentLoading
        }

        return state.copy(
            effectiveArguments = effectiveArguments,
            commandPreview = commandPreview,
            builderIssues = issues.distinct(),
            executionGuidance = executionGuidance,
            delegatedExecutorContextLabel = delegatedSelection?.label,
            delegatedExecutorSelectionReason = delegatedSelection?.routingReason ?: delegatedCompatibilityMessage,
            delegatedLastCheckedAtEpochMillis = delegatedSelection?.capabilitiesCheckedAtEpochMillis,
            delegatedCapabilitiesLoading = delegatedLoading,
            delegatedCapabilitiesStale = delegatedSelection?.capabilitiesStale ?: false,
        )
    }

    private fun tokenizeAndValidate(tool: ToolType, rawArguments: String): TokenValidationResult {
        val tokens = try {
            ArgumentTokenizer.tokenize(rawArguments)
        } catch (error: IllegalArgumentException) {
            return TokenValidationResult(
                arguments = emptyList(),
                issues = listOf(error.message ?: "Arguments are invalid."),
            )
        }
        val issues = CommandSafetyPolicy.validate(tool, tokens).map { "${it.field}: ${it.message}" }
        return TokenValidationResult(arguments = tokens, issues = issues)
    }

    private data class TokenValidationResult(
        val arguments: List<String>,
        val issues: List<String>,
    )

    private enum class DelegatedCapabilityLane {
        PRIMARY,
        LAN_AGENT,
    }

    companion object {
        fun factory(
            repository: DefaultScanRepository,
            automationScheduler: AutomationScheduler,
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                NmapToolViewModel(repository, automationScheduler) as T
        }
    }
}
