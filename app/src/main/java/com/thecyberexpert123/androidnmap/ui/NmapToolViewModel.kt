package com.thecyberexpert123.androidnmap.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.thecyberexpert123.androidnmap.data.AutomationScheduleSummary
import com.thecyberexpert123.androidnmap.data.DefaultScanRepository
import com.thecyberexpert123.androidnmap.data.EditableScanProfile
import com.thecyberexpert123.androidnmap.data.ScanProfileSummary
import com.thecyberexpert123.androidnmap.data.ScanRunSummary
import com.thecyberexpert123.androidnmap.settings.RemoteEndpointSettings
import com.thecyberexpert123.androidnmap.work.AutomationScheduler
import com.thecyberexpert123.nmaptool.contract.ArgumentTokenizer
import com.thecyberexpert123.nmaptool.contract.CommandPreview
import com.thecyberexpert123.nmaptool.contract.CommandSafetyPolicy
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidance
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidanceAdvisor
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidanceStatus
import com.thecyberexpert123.nmaptool.contract.ExecutionPreference
import com.thecyberexpert123.nmaptool.contract.NmapTimingTemplate
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.RunTrigger
import com.thecyberexpert123.nmaptool.contract.ScanPreset
import com.thecyberexpert123.nmaptool.contract.StructuredNmapArgumentComposer
import com.thecyberexpert123.nmaptool.contract.StructuredNmapOptions
import com.thecyberexpert123.nmaptool.contract.TargetParser
import com.thecyberexpert123.nmaptool.contract.ToolType
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
)

data class RemoteSettingsUiState(
    val baseUrl: String = "",
    val bearerToken: String = "",
)

data class CapabilityUiState(
    val loading: Boolean = false,
    val capabilities: RemoteCapabilitiesResponse? = null,
    val error: String? = null,
    val lastCheckedAtEpochMillis: Long? = null,
    val stale: Boolean = false,
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

    private val _builderState = MutableStateFlow(recalculate(ScanBuilderUiState()))
    val builderState: StateFlow<ScanBuilderUiState> = _builderState.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    init {
        val savedSettings = repository.readRemoteSettings()
        _remoteSettings.value = RemoteSettingsUiState(
            baseUrl = savedSettings.baseUrl,
            bearerToken = savedSettings.bearerToken,
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
        markCapabilitiesStale()
        refreshBuilderDerivedState()
    }

    fun updateRemoteToken(value: String) {
        _remoteSettings.update { it.copy(bearerToken = value) }
        markCapabilitiesStale()
        refreshBuilderDerivedState()
    }

    fun saveRemoteSettings() {
        viewModelScope.launch {
            val settings = RemoteEndpointSettings(
                baseUrl = remoteSettings.value.baseUrl,
                bearerToken = remoteSettings.value.bearerToken,
            )
            val result = repository.saveRemoteSettings(settings)
            if (result.isValid) {
                val capabilityRefreshError = if (settings.baseUrl.isNotBlank()) {
                    refreshCapabilitiesForSettings(settings)
                } else {
                    _capabilityState.value = CapabilityUiState()
                    refreshBuilderDerivedState()
                    null
                }
                _message.value = capabilityRefreshError?.let {
                    "Remote executor settings saved securely on-device, but capability refresh failed."
                } ?: "Remote executor settings saved securely on-device."
            } else {
                _message.value = result.issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }
            }
        }
    }

    fun refreshCapabilities() {
        viewModelScope.launch {
            refreshCapabilitiesForSettings(
                RemoteEndpointSettings(
                    baseUrl = remoteSettings.value.baseUrl,
                    bearerToken = remoteSettings.value.bearerToken,
                ),
                publishMessageOnFailure = true,
            )
        }
    }

    private suspend fun refreshCapabilitiesForSettings(
        settings: RemoteEndpointSettings,
        publishMessageOnFailure: Boolean = false,
    ): String? {
        val refreshStartedAt = System.currentTimeMillis()
        val previous = capabilityState.value
        _capabilityState.value = previous.copy(loading = true, error = null)
        var failureMessage: String? = null
        repository.fetchRemoteCapabilities(settings)
            .onSuccess { capabilities ->
                _capabilityState.value = CapabilityUiState(
                    capabilities = capabilities,
                    lastCheckedAtEpochMillis = refreshStartedAt,
                    stale = false,
                )
            }
            .onFailure { error ->
                failureMessage = error.message ?: "Failed to load remote capabilities."
                _capabilityState.value = CapabilityUiState(
                    error = failureMessage,
                    lastCheckedAtEpochMillis = refreshStartedAt,
                    stale = false,
                )
                if (publishMessageOnFailure) {
                    _message.value = failureMessage
                }
            }
        refreshBuilderDerivedState()
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

    private fun markCapabilitiesStale() {
        _capabilityState.update { current ->
            if (current.capabilities == null && current.error == null && current.lastCheckedAtEpochMillis == null) {
                current
            } else {
                current.copy(stale = true)
            }
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
        val commandPreview = if (effectiveArguments.isBlank()) {
            state.tool.binaryName + state.rawTargets.trim().let { suffix -> if (suffix.isBlank()) "" else " $suffix" }
        } else {
            val targets = TargetParser.parse(state.rawTargets)
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
        val baseGuidance = ExecutionGuidanceAdvisor.analyze(
            tool = state.tool,
            executionPreference = state.executionPreference,
            arguments = effectiveArgumentTokens,
            remoteConfigured = remoteSettings.value.baseUrl.isNotBlank(),
            remoteCapabilities = capabilitySnapshot.capabilities,
            remoteCapabilitiesStale = capabilitySnapshot.stale,
            localExecutionSupported = false,
            scheduleEnabled = state.scheduleEnabled,
        )
        val executionGuidance = if (issues.isNotEmpty()) {
            baseGuidance.copy(
                status = ExecutionGuidanceStatus.BLOCKED,
                summary = "Resolve builder issues before execution readiness can be trusted.",
                blockers = (listOf("Resolve the builder issues shown below.") + baseGuidance.blockers).distinct(),
            )
        } else {
            baseGuidance
        }

        return state.copy(
            effectiveArguments = effectiveArguments,
            commandPreview = commandPreview,
            builderIssues = issues.distinct(),
            executionGuidance = executionGuidance,
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
