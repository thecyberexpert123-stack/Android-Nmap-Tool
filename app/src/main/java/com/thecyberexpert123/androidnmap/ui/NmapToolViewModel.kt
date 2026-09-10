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
import com.thecyberexpert123.nmaptool.contract.ExecutionPreference
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.RunTrigger
import com.thecyberexpert123.nmaptool.contract.ScanPreset
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
    val rawArguments: String = "",
    val notes: String = "",
    val scheduleEnabled: Boolean = false,
    val scheduleMinutes: String = "60",
    val requireUnmeteredNetwork: Boolean = false,
    val selectedPreset: ScanPreset? = ScanPreset.QUICK_TCP,
)

data class RemoteSettingsUiState(
    val baseUrl: String = "",
    val bearerToken: String = "",
)

data class CapabilityUiState(
    val loading: Boolean = false,
    val capabilities: RemoteCapabilitiesResponse? = null,
    val error: String? = null,
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

    private val _builderState = MutableStateFlow(ScanBuilderUiState())
    val builderState: StateFlow<ScanBuilderUiState> = _builderState.asStateFlow()

    private val _remoteSettings = MutableStateFlow(RemoteSettingsUiState())
    val remoteSettings: StateFlow<RemoteSettingsUiState> = _remoteSettings.asStateFlow()

    private val _capabilityState = MutableStateFlow(CapabilityUiState())
    val capabilityState: StateFlow<CapabilityUiState> = _capabilityState.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    init {
        val savedSettings = repository.readRemoteSettings()
        _remoteSettings.value = RemoteSettingsUiState(
            baseUrl = savedSettings.baseUrl,
            bearerToken = savedSettings.bearerToken,
        )
        _builderState.update { state ->
            state.copy(rawArguments = ScanPreset.QUICK_TCP.suggestedArguments.joinToString(" "))
        }
    }

    fun consumeMessage() {
        _message.value = null
    }

    fun updateName(value: String) {
        _builderState.update { it.copy(name = value) }
    }

    fun updateTool(value: ToolType) {
        _builderState.update { it.copy(tool = value) }
    }

    fun updateExecutionPreference(value: ExecutionPreference) {
        _builderState.update { it.copy(executionPreference = value) }
    }

    fun updateTargets(value: String) {
        _builderState.update { it.copy(rawTargets = value) }
    }

    fun updateArguments(value: String) {
        _builderState.update { it.copy(rawArguments = value, selectedPreset = null) }
    }

    fun updateNotes(value: String) {
        _builderState.update { it.copy(notes = value) }
    }

    fun updateScheduleEnabled(value: Boolean) {
        _builderState.update { it.copy(scheduleEnabled = value) }
    }

    fun updateScheduleMinutes(value: String) {
        _builderState.update { it.copy(scheduleMinutes = value) }
    }

    fun updateRequireUnmeteredNetwork(value: Boolean) {
        _builderState.update { it.copy(requireUnmeteredNetwork = value) }
    }

    fun applyPreset(preset: ScanPreset) {
        _builderState.update {
            it.copy(
                tool = preset.tool,
                rawArguments = preset.suggestedArguments.joinToString(" "),
                selectedPreset = preset,
            )
        }
    }

    fun clearDraft() {
        _builderState.value = ScanBuilderUiState(
            rawArguments = ScanPreset.QUICK_TCP.suggestedArguments.joinToString(" "),
        )
    }

    fun loadProfile(profileId: String) {
        viewModelScope.launch {
            val profile = repository.loadEditableProfile(profileId)
            val schedule = repository.loadSchedule(profileId)
            if (profile == null) {
                _message.value = "Profile could not be loaded."
                return@launch
            }
            _builderState.value = ScanBuilderUiState(
                id = profile.id,
                name = profile.name,
                tool = profile.tool,
                executionPreference = profile.executionPreference,
                rawTargets = profile.rawTargets,
                rawArguments = profile.rawArguments,
                notes = profile.notes,
                scheduleEnabled = schedule?.enabled == true,
                scheduleMinutes = schedule?.repeatMinutes?.toString() ?: "60",
                requireUnmeteredNetwork = schedule?.requireUnmeteredNetwork == true,
                selectedPreset = ScanPreset.entries.firstOrNull {
                    it.tool == profile.tool && it.suggestedArguments.joinToString(" ") == profile.rawArguments.trim()
                },
            )
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
    }

    fun updateRemoteToken(value: String) {
        _remoteSettings.update { it.copy(bearerToken = value) }
    }

    fun saveRemoteSettings() {
        viewModelScope.launch {
            val result = repository.saveRemoteSettings(
                RemoteEndpointSettings(
                    baseUrl = remoteSettings.value.baseUrl,
                    bearerToken = remoteSettings.value.bearerToken,
                ),
            )
            _message.value = if (result.isValid) {
                "Remote executor settings saved securely on-device."
            } else {
                result.issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }
            }
        }
    }

    fun refreshCapabilities() {
        viewModelScope.launch {
            _capabilityState.value = CapabilityUiState(loading = true)
            repository.fetchRemoteCapabilities(
                settings = RemoteEndpointSettings(
                    baseUrl = remoteSettings.value.baseUrl,
                    bearerToken = remoteSettings.value.bearerToken,
                ),
            ).onSuccess { capabilities ->
                _capabilityState.value = CapabilityUiState(capabilities = capabilities)
            }.onFailure { error ->
                _capabilityState.value = CapabilityUiState(error = error.message)
                _message.value = error.message ?: "Failed to load remote capabilities."
            }
        }
    }

    private suspend fun persistCurrentDraft(showSuccessMessage: Boolean): String? {
        val scheduleMinutes = builderState.value.scheduleMinutes.toLongOrNull()
        if (builderState.value.scheduleEnabled && scheduleMinutes == null) {
            _message.value = "Schedule interval must be a whole number of minutes."
            return null
        }
        if (builderState.value.scheduleEnabled && scheduleMinutes != null && scheduleMinutes < 15L) {
            _message.value = "Periodic automation must be at least 15 minutes."
            return null
        }

        val draft = EditableScanProfile(
            id = builderState.value.id,
            name = builderState.value.name,
            tool = builderState.value.tool,
            executionPreference = builderState.value.executionPreference,
            rawTargets = builderState.value.rawTargets,
            rawArguments = builderState.value.rawArguments,
            notes = builderState.value.notes,
        )
        val result = repository.saveProfile(draft)
        if (!result.isValid) {
            _message.value = result.issues.joinToString(separator = "\n") { "${it.field}: ${it.message}" }
            return null
        }

        val profileId = result.value!!
        automationScheduler.syncSchedule(
            profileId = profileId,
            enabled = builderState.value.scheduleEnabled,
            repeatMinutes = scheduleMinutes,
            requireUnmeteredNetwork = builderState.value.requireUnmeteredNetwork,
        )
        _builderState.update { it.copy(id = profileId) }

        if (showSuccessMessage) {
            _message.value = if (builderState.value.scheduleEnabled) {
                "Profile saved and automation synchronized."
            } else {
                "Profile saved."
            }
        }
        return profileId
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
