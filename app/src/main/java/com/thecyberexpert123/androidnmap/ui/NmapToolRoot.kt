package com.thecyberexpert123.androidnmap.ui

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ElevatedAssistChip
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.thecyberexpert123.androidnmap.data.AutomationScheduleSummary
import com.thecyberexpert123.androidnmap.data.RunChangeKind
import com.thecyberexpert123.androidnmap.data.ScanProfileSummary
import com.thecyberexpert123.androidnmap.data.ScanRunSummary
import com.thecyberexpert123.androidnmap.reporting.ReportFileManager
import com.thecyberexpert123.androidnmap.reporting.buildExecutionReport
import com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityDescriptor
import com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityLevel
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidance
import com.thecyberexpert123.nmaptool.contract.ExecutionGuidanceStatus
import com.thecyberexpert123.nmaptool.contract.ExecutionPreference
import com.thecyberexpert123.nmaptool.contract.ExecutionRoute
import com.thecyberexpert123.nmaptool.contract.ExecutorCapabilityProfile
import com.thecyberexpert123.nmaptool.contract.ExecutorNodeKind
import com.thecyberexpert123.nmaptool.contract.ExecutorTransportKind
import com.thecyberexpert123.nmaptool.contract.NmapTimingTemplate
import com.thecyberexpert123.nmaptool.contract.PortFinding
import com.thecyberexpert123.nmaptool.contract.ResultParseSource
import com.thecyberexpert123.nmaptool.contract.ReportExportFormat
import com.thecyberexpert123.nmaptool.contract.RunStatus
import com.thecyberexpert123.nmaptool.contract.ScanPreset
import com.thecyberexpert123.nmaptool.contract.ToolType
import com.thecyberexpert123.nmaptool.contract.toExecutorCapabilityProfile
import java.text.DateFormat
import java.util.Date

private enum class AppTab(val label: String) {
    DASHBOARD("Dashboard"),
    BUILDER("Builder"),
    HISTORY("History"),
    AUTOMATION("Automation"),
    SETTINGS("Settings"),
}

private data class DashboardPortAlert(
    val profileName: String,
    val finding: PortFinding,
    val opened: Boolean,
)

private enum class HistoryReportFilter(val label: String, val tool: ToolType?, val failuresOnly: Boolean) {
    ALL("All tools", null, false),
    NMAP_ONLY("Nmap only", ToolType.NMAP, false),
    FAILURES_ONLY("Failures only", null, true),
}

@Composable
fun NmapToolRoot(viewModel: NmapToolViewModel) {
    val profiles by viewModel.profiles.collectAsStateWithLifecycle()
    val schedules by viewModel.schedules.collectAsStateWithLifecycle()
    val runs by viewModel.runs.collectAsStateWithLifecycle()
    val builderState by viewModel.builderState.collectAsStateWithLifecycle()
    val remoteSettings by viewModel.remoteSettings.collectAsStateWithLifecycle()
    val capabilityState by viewModel.capabilityState.collectAsStateWithLifecycle()
    val localCapabilityState by viewModel.localCapabilityState.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    var selectedTabIndex by rememberSaveable { mutableIntStateOf(AppTab.DASHBOARD.ordinal) }

    LaunchedEffect(message) {
        val currentMessage = message ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(currentMessage)
        viewModel.consumeMessage()
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(text = "Android Nmap Tool")
                        Text(
                            text = "Hybrid scanning for non-root Android",
                            style = MaterialTheme.typography.labelMedium,
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        bottomBar = {
            NavigationBar {
                AppTab.entries.forEachIndexed { index, tab ->
                    NavigationBarItem(
                        selected = selectedTabIndex == index,
                        onClick = { selectedTabIndex = index },
                        icon = {},
                        label = { Text(tab.label) },
                    )
                }
            }
        },
    ) { innerPadding ->
        when (AppTab.entries[selectedTabIndex]) {
            AppTab.DASHBOARD -> DashboardScreen(
                profiles = profiles,
                runs = runs,
                schedules = schedules,
                remoteSettings = remoteSettings,
                capabilityState = capabilityState,
                localCapabilityState = localCapabilityState,
                onNewScan = { selectedTabIndex = AppTab.BUILDER.ordinal },
                onEditProfile = {
                    viewModel.loadProfile(it)
                    selectedTabIndex = AppTab.BUILDER.ordinal
                },
                onRunProfile = viewModel::runExistingProfile,
                paddingValues = innerPadding,
            )

            AppTab.BUILDER -> BuilderScreen(
                state = builderState,
                capabilityState = capabilityState,
                onNameChanged = viewModel::updateName,
                onTargetsChanged = viewModel::updateTargets,
                onNotesChanged = viewModel::updateNotes,
                onToolSelected = viewModel::updateTool,
                onPreferenceSelected = viewModel::updateExecutionPreference,
                onScheduleEnabledChanged = viewModel::updateScheduleEnabled,
                onScheduleMinutesChanged = viewModel::updateScheduleMinutes,
                onRequireUnmeteredChanged = viewModel::updateRequireUnmeteredNetwork,
                onPresetSelected = viewModel::applyPreset,
                onSaveProfile = viewModel::saveProfile,
                onRunNow = viewModel::runCurrentDraft,
                onClearDraft = viewModel::clearDraft,
                onExpertArgumentsChanged = viewModel::updateExpertArguments,
                onSkipHostDiscoveryChanged = viewModel::updateSkipHostDiscovery,
                onServiceDetectionChanged = viewModel::updateServiceDetection,
                onDefaultScriptsChanged = viewModel::updateDefaultScripts,
                onOsDetectionChanged = viewModel::updateOsDetection,
                onTracerouteChanged = viewModel::updateTraceroute,
                onTimingTemplateChanged = viewModel::updateTimingTemplate,
                onPortListChanged = viewModel::updatePortList,
                onTopPortsChanged = viewModel::updateTopPorts,
                onScriptSelectionChanged = viewModel::updateScriptSelection,
                paddingValues = innerPadding,
            )

            AppTab.HISTORY -> HistoryScreen(
                runs = runs,
                onMessage = viewModel::publishMessage,
                paddingValues = innerPadding,
            )
            AppTab.AUTOMATION -> AutomationScreen(
                schedules = schedules,
                onEditProfile = {
                    viewModel.loadProfile(it)
                    selectedTabIndex = AppTab.BUILDER.ordinal
                },
                onRunProfile = viewModel::runExistingProfile,
                paddingValues = innerPadding,
            )

            AppTab.SETTINGS -> SettingsScreen(
                settingsState = remoteSettings,
                capabilityState = capabilityState,
                localCapabilityState = localCapabilityState,
                onBaseUrlChanged = viewModel::updateRemoteBaseUrl,
                onTokenChanged = viewModel::updateRemoteToken,
                onSave = viewModel::saveRemoteSettings,
                onRefreshCapabilities = viewModel::refreshCapabilities,
                onRefreshLocalCapabilities = viewModel::refreshLocalCapabilities,
                paddingValues = innerPadding,
            )
        }
    }
}

@Composable
private fun DashboardScreen(
    profiles: List<ScanProfileSummary>,
    runs: List<ScanRunSummary>,
    schedules: List<AutomationScheduleSummary>,
    remoteSettings: RemoteSettingsUiState,
    capabilityState: CapabilityUiState,
    localCapabilityState: LocalCapabilityUiState,
    onNewScan: () -> Unit,
    onEditProfile: (String) -> Unit,
    onRunProfile: (String) -> Unit,
    paddingValues: PaddingValues,
) {
    val recentRuns = runs.take(20)
    val observedHosts = recentRuns
        .flatMap { run -> run.parsedSummary.observedHosts }
        .map(String::trim)
        .filter(String::isNotEmpty)
        .toSet()
    val observedEndpoints = recentRuns
        .flatMap { run -> run.parsedSummary.portFindings }
        .map { finding -> "${finding.host.orEmpty()}|${finding.endpointLabel}" }
        .toSet()
    val recentPortAlerts = buildList {
        recentRuns.forEach { run ->
            run.newOpenPorts.forEach { finding ->
                add(DashboardPortAlert(profileName = run.profileName, finding = finding, opened = true))
            }
            run.closedPorts.forEach { finding ->
                add(DashboardPortAlert(profileName = run.profileName, finding = finding, opened = false))
            }
        }
    }.take(8)
    val changedRuns = recentRuns.count { it.newOpenPorts.isNotEmpty() || it.closedPorts.isNotEmpty() }
    val scheduledProfiles = profiles.count { it.scheduleEnabled }
    val failedProfiles = profiles.count { it.lastRunStatus == RunStatus.FAILED }
    val remoteConfigured = remoteSettings.baseUrl.isNotBlank()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                MetricCard(title = "Profiles", value = profiles.size.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Schedules", value = schedules.size.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Runs", value = runs.size.toString(), modifier = Modifier.weight(1f))
            }
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                MetricCard(title = "Observed hosts", value = observedHosts.size.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Open endpoints", value = observedEndpoints.size.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Port alerts", value = changedRuns.toString(), modifier = Modifier.weight(1f))
            }
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                MetricCard(title = "Scheduled profiles", value = scheduledProfiles.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Profiles with failed last run", value = failedProfiles.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Delegated executor configured", value = if (remoteConfigured) "Yes" else "No", modifier = Modifier.weight(1f))
            }
        }
        item {
            Card {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Execution posture", style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = "This app now treats scanning as capability-aware execution routing: Android-local socket probing stays on-device, while raw/fuller Nmap features are delegated to a legitimate executor that actually has them.",
                    )
                    Text(text = if (remoteConfigured) "Delegated executor base URL is configured." else "Delegated executor base URL is not configured yet.")
                    Text(
                        text = if (localCapabilityState.capabilities.networkAvailable) {
                            "Android-local engine sees an active network: ${localCapabilityState.capabilities.activeNetworkSummary.orEmpty()}"
                        } else {
                            "Android-local engine does not currently see an active network."
                        },
                    )
                    capabilityState.capabilities?.executorLabel?.takeIf(String::isNotBlank)?.let { label ->
                        Text(text = "Connected delegated executor label: $label")
                    }
                    capabilityState.error?.takeIf(String::isNotBlank)?.let { error ->
                        Text(text = "Latest delegated capability check error: $error", color = MaterialTheme.colorScheme.error)
                    }
                    ExecutorCapabilityProfileCard(profile = localCapabilityState.executorProfile)
                    capabilityState.capabilities?.let { remoteCapabilities ->
                        ExecutorCapabilityProfileCard(
                            profile = remoteCapabilities.executorProfile ?: remoteCapabilities.toExecutorCapabilityProfile(),
                        )
                    }
                    Text(
                        text = "Use Builder for structured Nmap controls, expert arguments, autonomous scheduling, saved profiles, and executor-aware planning.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(onClick = onNewScan) {
                        Text("Create scan profile")
                    }
                }
            }
        }
        item { SectionHeader(title = "Recent port changes") }
        if (recentPortAlerts.isEmpty()) {
            item {
                Card {
                    Text(
                        text = "No parsed open-port additions or removals are available yet. Run recurring Nmap profiles to populate change insights.",
                        modifier = Modifier.padding(16.dp),
                    )
                }
            }
        } else {
            items(recentPortAlerts) { alert ->
                DashboardPortAlertCard(alert = alert)
            }
        }
        item { SectionHeader(title = "Recent profiles") }
        items(profiles.take(5), key = { it.id }) { profile ->
            ProfileCard(profile = profile, onEdit = { onEditProfile(profile.id) }, onRun = { onRunProfile(profile.id) })
        }
        item { SectionHeader(title = "Recent runs") }
        items(runs.take(5), key = { it.id }) { run ->
            RunCard(run = run)
        }
    }
}

@Composable
private fun BuilderScreen(
    state: ScanBuilderUiState,
    capabilityState: CapabilityUiState,
    onNameChanged: (String) -> Unit,
    onTargetsChanged: (String) -> Unit,
    onNotesChanged: (String) -> Unit,
    onToolSelected: (ToolType) -> Unit,
    onPreferenceSelected: (ExecutionPreference) -> Unit,
    onScheduleEnabledChanged: (Boolean) -> Unit,
    onScheduleMinutesChanged: (String) -> Unit,
    onRequireUnmeteredChanged: (Boolean) -> Unit,
    onPresetSelected: (ScanPreset) -> Unit,
    onSaveProfile: () -> Unit,
    onRunNow: () -> Unit,
    onClearDraft: () -> Unit,
    onExpertArgumentsChanged: (String) -> Unit,
    onSkipHostDiscoveryChanged: (Boolean) -> Unit,
    onServiceDetectionChanged: (Boolean) -> Unit,
    onDefaultScriptsChanged: (Boolean) -> Unit,
    onOsDetectionChanged: (Boolean) -> Unit,
    onTracerouteChanged: (Boolean) -> Unit,
    onTimingTemplateChanged: (NmapTimingTemplate) -> Unit,
    onPortListChanged: (String) -> Unit,
    onTopPortsChanged: (String) -> Unit,
    onScriptSelectionChanged: (String) -> Unit,
    paddingValues: PaddingValues,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(text = "Scan builder", style = MaterialTheme.typography.headlineSmall)
        Text(
            text = "Build profiles with structured controls first, then use expert arguments for the remaining flags you intentionally need.",
            style = MaterialTheme.typography.bodyMedium,
        )

        OutlinedTextField(
            value = state.name,
            onValueChange = onNameChanged,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Profile name") },
            singleLine = true,
        )
        OutlinedTextField(
            value = state.rawTargets,
            onValueChange = onTargetsChanged,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Targets") },
            supportingText = { Text("One host/range/CIDR per line, or separate multiple targets with commas.") },
            minLines = 3,
        )

        SelectorSection(title = "Tool") {
            ToolType.entries.forEach { tool ->
                FilterChip(
                    selected = state.tool == tool,
                    onClick = { onToolSelected(tool) },
                    label = { Text(tool.name) },
                )
            }
        }

        SelectorSection(title = "Execution mode") {
            ExecutionPreference.entries.forEach { preference ->
                FilterChip(
                    selected = state.executionPreference == preference,
                    onClick = { onPreferenceSelected(preference) },
                    label = { Text(preference.name.replace('_', ' ')) },
                )
            }
        }

        SelectorSection(title = "Presets") {
            ScanPreset.entries.forEach { preset ->
                ElevatedAssistChip(
                    onClick = { onPresetSelected(preset) },
                    label = { Text(preset.displayName) },
                )
            }
        }

        if (state.tool == ToolType.NMAP) {
            StructuredNmapOptionsCard(
                state = state,
                onSkipHostDiscoveryChanged = onSkipHostDiscoveryChanged,
                onServiceDetectionChanged = onServiceDetectionChanged,
                onDefaultScriptsChanged = onDefaultScriptsChanged,
                onOsDetectionChanged = onOsDetectionChanged,
                onTracerouteChanged = onTracerouteChanged,
                onTimingTemplateChanged = onTimingTemplateChanged,
                onPortListChanged = onPortListChanged,
                onTopPortsChanged = onTopPortsChanged,
                onScriptSelectionChanged = onScriptSelectionChanged,
            )
        }

        OutlinedTextField(
            value = state.expertArguments,
            onValueChange = onExpertArgumentsChanged,
            modifier = Modifier.fillMaxWidth(),
            label = {
                Text(if (state.tool == ToolType.NMAP) "Extra expert arguments" else "Arguments")
            },
            supportingText = {
                Text(
                    if (state.tool == ToolType.NMAP) {
                        "Use this only for flags not already covered by the structured Nmap controls."
                    } else {
                        "Full CLI-style argument entry for ${state.tool.binaryName}."
                    },
                )
            },
            minLines = 3,
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )

        PreviewCard(title = "Effective arguments", body = state.effectiveArguments.ifBlank { "No arguments selected." })
        PreviewCard(title = "Command preview", body = state.commandPreview)
        ExecutionGuidanceCard(
            guidance = state.executionGuidance,
            capabilityState = capabilityState,
        )

        if (state.builderIssues.isNotEmpty()) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(text = "Builder issues", style = MaterialTheme.typography.titleMedium)
                    state.builderIssues.forEach { issue ->
                        Text(text = "• $issue", color = MaterialTheme.colorScheme.onErrorContainer)
                    }
                }
            }
        }

        OutlinedTextField(
            value = state.notes,
            onValueChange = onNotesChanged,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Operator notes") },
            minLines = 2,
        )

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(text = "Autonomous mode", style = MaterialTheme.typography.titleMedium)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = state.scheduleEnabled, onCheckedChange = onScheduleEnabledChanged)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(text = "Enable scheduled recurring scans")
                }
                if (state.scheduleEnabled) {
                    OutlinedTextField(
                        value = state.scheduleMinutes,
                        onValueChange = onScheduleMinutesChanged,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Repeat every minutes") },
                        supportingText = { Text("WorkManager periodic jobs require at least 15 minutes.") },
                        singleLine = true,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = state.requireUnmeteredNetwork,
                            onCheckedChange = onRequireUnmeteredChanged,
                        )
                        Text(text = "Require unmetered network")
                    }
                }
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(onClick = onSaveProfile, modifier = Modifier.weight(1f)) {
                Text("Save profile")
            }
            Button(onClick = onRunNow, modifier = Modifier.weight(1f)) {
                Text("Run now")
            }
        }
        TextButton(onClick = onClearDraft, modifier = Modifier.align(Alignment.End)) {
            Text("Clear draft")
        }
    }
}

@Composable
private fun StructuredNmapOptionsCard(
    state: ScanBuilderUiState,
    onSkipHostDiscoveryChanged: (Boolean) -> Unit,
    onServiceDetectionChanged: (Boolean) -> Unit,
    onDefaultScriptsChanged: (Boolean) -> Unit,
    onOsDetectionChanged: (Boolean) -> Unit,
    onTracerouteChanged: (Boolean) -> Unit,
    onTimingTemplateChanged: (NmapTimingTemplate) -> Unit,
    onPortListChanged: (String) -> Unit,
    onTopPortsChanged: (String) -> Unit,
    onScriptSelectionChanged: (String) -> Unit,
) {
    Card {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(text = "Structured Nmap options", style = MaterialTheme.typography.titleMedium)
            SettingSwitchRow(
                title = "Skip host discovery (-Pn)",
                checked = state.skipHostDiscovery,
                onCheckedChange = onSkipHostDiscoveryChanged,
            )
            SettingSwitchRow(
                title = "Service detection (-sV, limited locally)",
                checked = state.enableServiceDetection,
                onCheckedChange = onServiceDetectionChanged,
            )
            SettingSwitchRow(
                title = "Default scripts (-sC)",
                checked = state.enableDefaultScripts,
                onCheckedChange = onDefaultScriptsChanged,
            )
            SettingSwitchRow(
                title = "OS detection (-O, inference locally)",
                checked = state.enableOsDetection,
                onCheckedChange = onOsDetectionChanged,
            )
            SettingSwitchRow(
                title = "Traceroute (--traceroute)",
                checked = state.enableTraceroute,
                onCheckedChange = onTracerouteChanged,
            )

            SelectorSection(title = "Timing template") {
                NmapTimingTemplate.entries.forEach { template ->
                    FilterChip(
                        selected = state.timingTemplate == template,
                        onClick = { onTimingTemplateChanged(template) },
                        label = { Text(template.name) },
                    )
                }
            }

            OutlinedTextField(
                value = state.portList,
                onValueChange = onPortListChanged,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Port list (-p)") },
                supportingText = { Text("Example: 22,80,443 or 1-1024") },
                singleLine = true,
            )
            OutlinedTextField(
                value = state.topPorts,
                onValueChange = onTopPortsChanged,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Top ports (--top-ports)") },
                supportingText = { Text("Use this instead of a manual port list when you want ranked common ports.") },
                singleLine = true,
            )
            OutlinedTextField(
                value = state.scriptSelection,
                onValueChange = onScriptSelectionChanged,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Script selection (--script)") },
                supportingText = { Text("Example: default,safe or http-title") },
                singleLine = true,
            )
        }
    }
}

@Composable
private fun ExecutionGuidanceCard(
    guidance: ExecutionGuidance,
    capabilityState: CapabilityUiState,
) {
    val containerColor = when (guidance.status) {
        ExecutionGuidanceStatus.READY -> MaterialTheme.colorScheme.secondaryContainer
        ExecutionGuidanceStatus.CAUTION -> MaterialTheme.colorScheme.tertiaryContainer
        ExecutionGuidanceStatus.BLOCKED -> MaterialTheme.colorScheme.errorContainer
    }
    val contentColor = when (guidance.status) {
        ExecutionGuidanceStatus.READY -> MaterialTheme.colorScheme.onSecondaryContainer
        ExecutionGuidanceStatus.CAUTION -> MaterialTheme.colorScheme.onTertiaryContainer
        ExecutionGuidanceStatus.BLOCKED -> MaterialTheme.colorScheme.onErrorContainer
    }

    Card(colors = CardDefaults.cardColors(containerColor = containerColor, contentColor = contentColor)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "Execution guidance", style = MaterialTheme.typography.titleMedium)
            Text(text = guidance.summary, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            Text(
                text = "Likely route: ${guidance.likelyRoute?.name ?: "UNRESOLVED"}",
                style = MaterialTheme.typography.bodySmall,
            )
            guidance.likelyExecutorTitle?.let { executorTitle ->
                Text(
                    text = "Likely executor: $executorTitle",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            capabilityState.lastCheckedAtEpochMillis?.let { checkedAt ->
                Text(
                    text = if (capabilityState.stale) {
                        "Delegated capability check is stale. Last checked ${formatTimestamp(checkedAt)}."
                    } else {
                        "Delegated capabilities last checked ${formatTimestamp(checkedAt)}."
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (capabilityState.loading) {
                Text(text = "Refreshing remote capability data…", style = MaterialTheme.typography.bodySmall)
            }
            if (guidance.blockers.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(text = "Blockers", style = MaterialTheme.typography.titleSmall)
                    guidance.blockers.forEach { blocker ->
                        Text(text = "• $blocker", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            if (guidance.warnings.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(text = "Warnings", style = MaterialTheme.typography.titleSmall)
                    guidance.warnings.forEach { warning ->
                        Text(text = "• $warning", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            if (guidance.notes.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(text = "Notes", style = MaterialTheme.typography.titleSmall)
                    guidance.notes.forEach { note ->
                        Text(text = "• $note", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun HistoryScreen(
    runs: List<ScanRunSummary>,
    onMessage: (String) -> Unit,
    paddingValues: PaddingValues,
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    var selectedFormatIndex by rememberSaveable { mutableIntStateOf(ReportExportFormat.MARKDOWN.ordinal) }
    var selectedFilterIndex by rememberSaveable { mutableIntStateOf(HistoryReportFilter.ALL.ordinal) }
    var selectedWindowIndex by rememberSaveable { mutableIntStateOf(1) }
    var pendingExportContent by remember { androidx.compose.runtime.mutableStateOf<String?>(null) }
    var pendingExportFileName by remember { androidx.compose.runtime.mutableStateOf<String?>(null) }

    val selectedFormat = ReportExportFormat.entries[selectedFormatIndex]
    val selectedFilter = HistoryReportFilter.entries[selectedFilterIndex]
    val windowSizes = listOf(10, 25, 100)
    val selectedWindow = windowSizes[selectedWindowIndex.coerceIn(windowSizes.indices)]
    val filteredRuns = runs.asSequence()
        .filter { run -> selectedFilter.tool == null || run.tool == selectedFilter.tool }
        .filter { run -> !selectedFilter.failuresOnly || run.status == RunStatus.FAILED }
        .take(selectedWindow)
        .toList()
    val structuredRuns = runs.count { it.parsedSummary.parseSource == ResultParseSource.STRUCTURED_NMAP_XML }
    val failedRuns = runs.count { it.status == RunStatus.FAILED }
    val remoteRuns = runs.count { it.route == ExecutionRoute.REMOTE }
    val reportText = buildExecutionReport(
        runs = runs,
        format = selectedFormat,
        title = "Android Nmap Tool execution report",
        maxRuns = selectedWindow,
        toolFilter = selectedFilter.tool,
        failuresOnly = selectedFilter.failuresOnly,
    )
    val suggestedFileName = ReportFileManager.buildSuggestedFileName(
        format = selectedFormat,
        filterLabel = selectedFilter.label,
        maxRuns = selectedWindow,
    )
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*"),
    ) { destinationUri ->
        val reportContent = pendingExportContent
        val fileName = pendingExportFileName
        pendingExportContent = null
        pendingExportFileName = null
        if (destinationUri == null || reportContent == null || fileName == null) {
            return@rememberLauncherForActivityResult
        }
        runCatching {
            ReportFileManager.writeReportToUri(context, destinationUri, reportContent)
        }.onSuccess {
            onMessage("Report exported as $fileName.")
        }.onFailure { error ->
            onMessage(error.message ?: "Failed to export the report file.")
        }
    }
    val previewText = reportText.take(4_500).let { prefix ->
        if (prefix.length == reportText.length) prefix else "$prefix\n…[preview truncated; export or share for the full report]"
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(text = "Execution history", style = MaterialTheme.typography.headlineSmall)
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                MetricCard(title = "Total runs", value = runs.size.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Failed runs", value = failedRuns.toString(), modifier = Modifier.weight(1f))
                MetricCard(title = "Structured parsed", value = structuredRuns.toString(), modifier = Modifier.weight(1f))
            }
        }
        item {
            MetricCard(
                title = "Remote-routed runs",
                value = remoteRuns.toString(),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            Card {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(text = "Report export", style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = "Generate a shareable summary from saved run history. This is a reporting/export preview only; it does not claim stronger runtime verification than the captured runs actually provide.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    SelectorSection(title = "Format") {
                        ReportExportFormat.entries.forEach { format ->
                            FilterChip(
                                selected = selectedFormat == format,
                                onClick = { selectedFormatIndex = format.ordinal },
                                label = { Text(format.name) },
                            )
                        }
                    }
                    SelectorSection(title = "Run filter") {
                        HistoryReportFilter.entries.forEach { filter ->
                            FilterChip(
                                selected = selectedFilter == filter,
                                onClick = { selectedFilterIndex = filter.ordinal },
                                label = { Text(filter.label) },
                            )
                        }
                    }
                    SelectorSection(title = "Window size") {
                        windowSizes.forEachIndexed { index, count ->
                            FilterChip(
                                selected = selectedWindowIndex == index,
                                onClick = { selectedWindowIndex = index },
                                label = { Text("Latest $count") },
                            )
                        }
                    }
                    Text(
                        text = "Filtered runs included: ${filteredRuns.size}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Button(onClick = {
                            clipboardManager.setText(AnnotatedString(reportText))
                            onMessage("Report copied to clipboard.")
                        }) {
                            Text("Copy report")
                        }
                        Button(
                            onClick = {
                                pendingExportContent = reportText
                                pendingExportFileName = suggestedFileName
                                exportLauncher.launch(suggestedFileName)
                            },
                        ) {
                            Text("Export file")
                        }
                        Button(
                            onClick = {
                                runCatching {
                                    val shareIntent = ReportFileManager.createShareIntent(
                                        context = context,
                                        format = selectedFormat,
                                        fileName = suggestedFileName,
                                        content = reportText,
                                    )
                                    context.startActivity(
                                        Intent.createChooser(shareIntent, "Share execution report").apply {
                                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                        },
                                    )
                                    onMessage("Share sheet opened for $suggestedFileName.")
                                }.onFailure { error ->
                                    onMessage(error.message ?: "Failed to prepare a shareable report file.")
                                }
                            },
                        ) {
                            Text("Share report")
                        }
                    }
                    Text(
                        text = "Suggested filename: $suggestedFileName",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    PreviewCard(title = "Report preview", body = previewText)
                }
            }
        }
        items(runs, key = { it.id }) { run ->
            RunCard(run = run)
        }
    }
}

@Composable
private fun AutomationScreen(
    schedules: List<AutomationScheduleSummary>,
    onEditProfile: (String) -> Unit,
    onRunProfile: (String) -> Unit,
    paddingValues: PaddingValues,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(text = "Automation", style = MaterialTheme.typography.headlineSmall)
        }
        items(schedules, key = { it.profileId }) { schedule ->
            Card {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = schedule.profileName, style = MaterialTheme.typography.titleMedium)
                    Text(text = "Every ${schedule.repeatMinutes} minutes")
                    Text(text = if (schedule.requireUnmeteredNetwork) "Unmetered network required" else "Any connected network")
                    schedule.lastRunStartedAtEpochMillis?.let { lastRunAt ->
                        Text(
                            text = "Last run: ${schedule.lastRunStatus?.name ?: "UNKNOWN"} • ${formatTimestamp(lastRunAt)}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        TextButton(onClick = { onEditProfile(schedule.profileId) }) {
                            Text("Edit")
                        }
                        TextButton(onClick = { onRunProfile(schedule.profileId) }) {
                            Text("Run now")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    settingsState: RemoteSettingsUiState,
    capabilityState: CapabilityUiState,
    localCapabilityState: LocalCapabilityUiState,
    onBaseUrlChanged: (String) -> Unit,
    onTokenChanged: (String) -> Unit,
    onSave: () -> Unit,
    onRefreshCapabilities: () -> Unit,
    onRefreshLocalCapabilities: () -> Unit,
    paddingValues: PaddingValues,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(text = "Execution settings", style = MaterialTheme.typography.headlineSmall)
        Text(
            text = "Android-local mode now provides a real stock-Android baseline for socket-level probing, curated service identification, and evidence-based fingerprint inference, while delegated execution remains the honest path to broader/full Nmap functionality on modern non-root devices. The bearer token is stored encrypted with Android Keystore. Saving delegated-executor settings also re-checks backend capabilities when a base URL is configured.",
        )
        ExecutorCapabilityProfileCard(
            profile = localCapabilityState.executorProfile,
            subtitle = "Snapshot captured ${formatTimestamp(localCapabilityState.lastCheckedAtEpochMillis)}",
            footer = {
                Button(onClick = onRefreshLocalCapabilities) {
                    Text("Refresh local snapshot")
                }
            },
        )
        Text(text = "Delegated executor settings", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(
            value = settingsState.baseUrl,
            onValueChange = onBaseUrlChanged,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Base URL") },
            supportingText = { Text("Example: https://scanner.example.com") },
            singleLine = true,
        )
        OutlinedTextField(
            value = settingsState.bearerToken,
            onValueChange = onTokenChanged,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Bearer token") },
            supportingText = { Text("Optional. Leave empty only on intentionally trusted private deployments.") },
            singleLine = true,
        )
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(onClick = onSave) {
                Text("Save settings")
            }
            Button(onClick = onRefreshCapabilities) {
                Text(if (capabilityState.loading) "Checking..." else "Refresh capabilities")
            }
        }
        capabilityState.lastCheckedAtEpochMillis?.let { checkedAt ->
            Text(
                text = if (capabilityState.stale) {
                    "Capability data is stale relative to unsaved settings changes. Last checked ${formatTimestamp(checkedAt)}."
                } else {
                    "Last capability check: ${formatTimestamp(checkedAt)}"
                },
                style = MaterialTheme.typography.bodySmall,
            )
        }
        capabilityState.capabilities?.let { capabilities ->
            ExecutorCapabilityProfileCard(
                profile = capabilities.executorProfile ?: capabilities.toExecutorCapabilityProfile(),
                subtitle = capabilityState.lastCheckedAtEpochMillis?.let { checkedAt ->
                    if (capabilityState.stale) {
                        "Snapshot captured ${formatTimestamp(checkedAt)} and is stale relative to unsaved settings changes."
                    } else {
                        "Snapshot captured ${formatTimestamp(checkedAt)}"
                    }
                },
                footer = {
                    if (capabilities.nmapVersion?.isNotBlank() == true) {
                        Text(text = "nmap version: ${capabilities.nmapVersion}", style = MaterialTheme.typography.bodySmall)
                    }
                    if (capabilities.ncatVersion?.isNotBlank() == true) {
                        Text(text = "ncat version: ${capabilities.ncatVersion}", style = MaterialTheme.typography.bodySmall)
                    }
                    if (capabilities.npingVersion?.isNotBlank() == true) {
                        Text(text = "nping version: ${capabilities.npingVersion}", style = MaterialTheme.typography.bodySmall)
                    }
                    Text(text = "target policy: ${capabilities.targetPolicySummary}", style = MaterialTheme.typography.bodySmall)
                },
            )
        }
        capabilityState.error?.let { error ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text(text = error, modifier = Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onErrorContainer)
            }
        }
    }
}

@Composable
private fun ExecutorCapabilityProfileCard(
    profile: ExecutorCapabilityProfile,
    subtitle: String? = null,
    footer: (@Composable () -> Unit)? = null,
) {
    Card {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = profile.label, style = MaterialTheme.typography.titleMedium)
            Text(
                text = "${formatExecutorNodeKind(profile.kind)} • ${formatExecutorTransportKind(profile.transport)}",
                style = MaterialTheme.typography.bodySmall,
            )
            subtitle?.takeIf(String::isNotBlank)?.let {
                Text(text = it, style = MaterialTheme.typography.bodySmall)
            }
            Text(text = "available: ${profile.available}", style = MaterialTheme.typography.bodySmall)
            Text(text = "requires authentication: ${profile.requiresAuthentication}", style = MaterialTheme.typography.bodySmall)
            Text(text = "privileged/raw access: ${profile.privileged}", style = MaterialTheme.typography.bodySmall)
            profile.activeNetworkSummary?.takeIf(String::isNotBlank)?.let {
                Text(text = "network context: $it", style = MaterialTheme.typography.bodySmall)
            }
            profile.maxTargetsPerRun?.let {
                Text(text = "max targets per run: $it", style = MaterialTheme.typography.bodySmall)
            }
            profile.maxArgumentsPerRun?.let {
                Text(text = "max arguments per run: $it", style = MaterialTheme.typography.bodySmall)
            }
            profile.maxPortsPerTarget?.let {
                Text(text = "max ports per target: $it", style = MaterialTheme.typography.bodySmall)
            }
            profile.maxTotalProbesPerRun?.let {
                Text(text = "max total probes per run: $it", style = MaterialTheme.typography.bodySmall)
            }
            profile.maxConcurrentExecutions?.let {
                Text(text = "max concurrent executions: $it", style = MaterialTheme.typography.bodySmall)
            }
            profile.outputCaptureLimitBytes?.let {
                Text(text = "captured output limit: $it bytes", style = MaterialTheme.typography.bodySmall)
            }
            Text(text = profile.advisory, style = MaterialTheme.typography.bodySmall)
            if (profile.capabilities.isNotEmpty()) {
                Text(text = "Capability matrix", style = MaterialTheme.typography.titleSmall)
                profile.capabilities.forEach { capability ->
                    ExecutionCapabilityRow(capability = capability)
                }
            }
            footer?.invoke()
        }
    }
}

@Composable
private fun ExecutionCapabilityRow(capability: ExecutionCapabilityDescriptor) {
    Text(
        text = "• ${formatCapabilityId(capability)}: ${formatCapabilityLevel(capability.level)} — ${capability.summary}",
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun MetricCard(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(text = title, style = MaterialTheme.typography.labelLarge)
            Text(text = value, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun ProfileCard(
    profile: ScanProfileSummary,
    onEdit: () -> Unit,
    onRun: () -> Unit,
) {
    Card {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = profile.name, style = MaterialTheme.typography.titleMedium)
            Text(text = "${profile.tool.name} • ${profile.executionPreference.name.replace('_', ' ')}")
            Text(text = "Targets: ${profile.targetSummary}", maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                text = profile.scheduleRepeatMinutes?.let { minutes ->
                    if (profile.scheduleEnabled) "Scheduled every $minutes minutes" else "Schedule saved but disabled"
                } ?: "No recurring schedule",
                style = MaterialTheme.typography.bodySmall,
            )
            profile.lastRunStartedAtEpochMillis?.let { lastRunAt ->
                val route = profile.lastRunRoute?.name ?: "UNKNOWN"
                val status = profile.lastRunStatus?.name ?: "UNKNOWN"
                Text(
                    text = "Last run: $status via $route • ${formatTimestamp(lastRunAt)}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (profile.argumentsPreview.isNotBlank()) {
                Text(
                    text = profile.argumentsPreview,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                TextButton(onClick = onEdit) { Text("Edit") }
                TextButton(onClick = onRun) { Text("Run") }
            }
        }
    }
}

@Composable
private fun DashboardPortAlertCard(alert: DashboardPortAlert) {
    val containerColor = if (alert.opened) {
        MaterialTheme.colorScheme.tertiaryContainer
    } else {
        MaterialTheme.colorScheme.errorContainer
    }
    Card(colors = CardDefaults.cardColors(containerColor = containerColor)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = alert.profileName, style = MaterialTheme.typography.titleMedium)
            Text(
                text = if (alert.opened) "New open endpoint detected" else "Previously open endpoint missing",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
            )
            Text(
                text = formatFinding(alert.finding),
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
        }
    }
}

@Composable
private fun RunCard(run: ScanRunSummary) {
    val changeContainerColor = when (run.changeKind) {
        RunChangeKind.BASELINE -> MaterialTheme.colorScheme.secondaryContainer
        RunChangeKind.UNCHANGED -> MaterialTheme.colorScheme.surfaceVariant
        RunChangeKind.CHANGED -> MaterialTheme.colorScheme.tertiaryContainer
    }
    Card {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = run.profileName, style = MaterialTheme.typography.titleMedium)
            Text(text = "${run.status.name} via ${run.route.name} • ${run.trigger.name}")
            Text(
                text = buildString {
                    append("Parsed via ")
                    append(formatParseSource(run.parsedSummary.parseSource))
                    append(" • ")
                    append(formatDuration(run.durationMillis))
                    append(" • ")
                    append(run.parsedSummary.observedHosts.size)
                    append(" hosts • ")
                    append(run.parsedSummary.portFindings.size)
                    append(" endpoints")
                },
                style = MaterialTheme.typography.bodySmall,
            )
            if (!run.requestId.isNullOrBlank() || !run.executorLabel.isNullOrBlank()) {
                Text(
                    text = buildString {
                        run.executorLabel?.takeIf(String::isNotBlank)?.let {
                            append("Executor ")
                            append(it)
                        }
                        run.requestId?.takeIf(String::isNotBlank)?.let {
                            if (isNotEmpty()) append(" • ")
                            append("Request ")
                            append(it)
                        }
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Card(colors = CardDefaults.cardColors(containerColor = changeContainerColor)) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = run.changeSummary,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        text = run.parsedSummary.overview,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                    )
                }
            }
            if (run.parsedSummary.warnings.isNotEmpty()) {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(text = "Capture / parsing warnings", style = MaterialTheme.typography.titleSmall)
                        run.parsedSummary.warnings.forEach { warning ->
                            Text(
                                text = "• $warning",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                        }
                    }
                }
            }
            if (run.parsedSummary.highlights.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    run.parsedSummary.highlights.forEach { highlight ->
                        Text(
                            text = "• $highlight",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
            if (run.newOpenPorts.isNotEmpty()) {
                PreviewCard(
                    title = "New open ports since previous run",
                    body = run.newOpenPorts.joinToString(separator = "\n", transform = ::formatFinding),
                )
            }
            if (run.closedPorts.isNotEmpty()) {
                PreviewCard(
                    title = "Previously open ports no longer present",
                    body = run.closedPorts.joinToString(separator = "\n", transform = ::formatFinding),
                )
            }
            if (run.parsedSummary.observedHosts.isNotEmpty()) {
                PreviewCard(
                    title = "Observed hosts",
                    body = run.parsedSummary.observedHosts.joinToString(separator = "\n"),
                )
            }
            if (run.parsedSummary.portFindings.isNotEmpty()) {
                PreviewCard(
                    title = "Parsed findings",
                    body = run.parsedSummary.portFindings.joinToString(separator = "\n", transform = ::formatFinding),
                )
            }
            Text(
                text = run.commandPreview,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
            if (run.message.isNotBlank()) {
                Text(text = run.message)
            }
            if (run.stderr.isNotBlank()) {
                Text(
                    text = run.stderr,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    maxLines = 6,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (run.stdout.isNotBlank()) {
                HorizontalDivider()
                Text(
                    text = run.stdout,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    maxLines = 8,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                text = "Started ${formatTimestamp(run.startedAtEpochMillis)}",
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

@Composable
private fun PreviewCard(
    title: String,
    body: String,
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(
                text = body,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
        }
    }
}

@Composable
private fun SettingSwitchRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Switch(checked = checked, onCheckedChange = onCheckedChange)
        Spacer(modifier = Modifier.width(12.dp))
        Text(text = title)
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(text = title, style = MaterialTheme.typography.titleLarge)
}

@Composable
private fun SelectorSection(
    title: String,
    content: @Composable () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(text = title, style = MaterialTheme.typography.titleMedium)
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            content()
        }
    }
}

private fun formatExecutorNodeKind(kind: ExecutorNodeKind): String = when (kind) {
    ExecutorNodeKind.ANDROID_LOCAL -> "Android local executor"
    ExecutorNodeKind.REMOTE_NMAP -> "Delegated Nmap executor"
    ExecutorNodeKind.LAN_AGENT -> "Delegated LAN agent"
    ExecutorNodeKind.UNKNOWN -> "Unknown executor"
}

private fun formatExecutorTransportKind(transport: ExecutorTransportKind): String = when (transport) {
    ExecutorTransportKind.ON_DEVICE -> "On-device transport"
    ExecutorTransportKind.HTTPS -> "HTTPS transport"
    ExecutorTransportKind.VPN_TUNNEL -> "VPN tunnel transport"
    ExecutorTransportKind.PRIVATE_OVERLAY -> "Private overlay transport"
    ExecutorTransportKind.UNKNOWN -> "Unknown transport"
}

private fun formatCapabilityId(capability: ExecutionCapabilityDescriptor): String = when (capability.id) {
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.TCP_CONNECT_SCAN -> "TCP connect scan"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.UDP_APPLICATION_PROBES -> "UDP application probes"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.PASSIVE_BANNER_CAPTURE -> "Passive banner capture"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.CURATED_SERVICE_DETECTION -> "Curated service detection"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.ANDROID_FINGERPRINT_INFERENCE -> "Android-local fingerprint inference"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.RAW_PACKET_PROBES -> "Raw packet probes"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.NMAP_OS_DETECTION -> "Nmap OS detection"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.NSE_SCRIPTS -> "NSE scripts"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.TRACEROUTE -> "Traceroute"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.STRUCTURED_NMAP_XML -> "Structured Nmap XML"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.AUTHENTICATED_API -> "Authenticated API"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.AUDIT_LOGGING -> "Audit logging"
    com.thecyberexpert123.nmaptool.contract.ExecutionCapabilityId.CONCURRENCY_GOVERNANCE -> "Concurrency governance"
}

private fun formatCapabilityLevel(level: ExecutionCapabilityLevel): String = when (level) {
    ExecutionCapabilityLevel.SUPPORTED -> "supported"
    ExecutionCapabilityLevel.LIMITED -> "limited"
    ExecutionCapabilityLevel.UNSUPPORTED -> "unsupported"
}

private fun formatFinding(finding: PortFinding): String = buildString {
    finding.host?.takeIf(String::isNotBlank)?.let {
        append(it)
        append(' ')
    }
    append(finding.endpointLabel)
    append(' ')
    append(finding.state)
    append(' ')
    append(finding.service)
    if (finding.details.isNotBlank()) {
        append(" — ")
        append(finding.details)
    }
}

private fun formatParseSource(source: ResultParseSource): String = when (source) {
    ResultParseSource.STRUCTURED_NMAP_XML -> "structured Nmap XML"
    ResultParseSource.HEURISTIC_TEXT -> "heuristic text parsing"
    ResultParseSource.NONE -> "no parsed content"
}

private fun formatDuration(durationMillis: Long): String {
    val totalSeconds = durationMillis / 1_000
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    return if (minutes > 0) {
        "${minutes}m ${seconds}s"
    } else {
        "${seconds}s"
    }
}

private fun formatTimestamp(epochMillis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(epochMillis))
