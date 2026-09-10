package com.thecyberexpert123.androidnmap.ui

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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.thecyberexpert123.androidnmap.data.AutomationScheduleSummary
import com.thecyberexpert123.androidnmap.data.RunChangeKind
import com.thecyberexpert123.androidnmap.data.ScanProfileSummary
import com.thecyberexpert123.androidnmap.data.ScanRunSummary
import com.thecyberexpert123.nmaptool.contract.ExecutionPreference
import com.thecyberexpert123.nmaptool.contract.NmapTimingTemplate
import com.thecyberexpert123.nmaptool.contract.ScanPreset
import com.thecyberexpert123.nmaptool.contract.ToolType
import java.text.DateFormat
import java.util.Date

private enum class AppTab(val label: String) {
    DASHBOARD("Dashboard"),
    BUILDER("Builder"),
    HISTORY("History"),
    AUTOMATION("Automation"),
    SETTINGS("Settings"),
}

@Composable
fun NmapToolRoot(viewModel: NmapToolViewModel) {
    val profiles by viewModel.profiles.collectAsStateWithLifecycle()
    val schedules by viewModel.schedules.collectAsStateWithLifecycle()
    val runs by viewModel.runs.collectAsStateWithLifecycle()
    val builderState by viewModel.builderState.collectAsStateWithLifecycle()
    val remoteSettings by viewModel.remoteSettings.collectAsStateWithLifecycle()
    val capabilityState by viewModel.capabilityState.collectAsStateWithLifecycle()
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
                capabilityState = capabilityState,
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

            AppTab.HISTORY -> HistoryScreen(runs = runs, paddingValues = innerPadding)
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
                onBaseUrlChanged = viewModel::updateRemoteBaseUrl,
                onTokenChanged = viewModel::updateRemoteToken,
                onSave = viewModel::saveRemoteSettings,
                onRefreshCapabilities = viewModel::refreshCapabilities,
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
    capabilityState: CapabilityUiState,
    onNewScan: () -> Unit,
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
            Card {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Execution posture", style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = capabilityState.capabilities?.advisory
                            ?: "Remote execution is the primary path for non-root Android, while local execution remains capability-gated.",
                    )
                    Text(
                        text = "Use Builder for structured Nmap controls, expert arguments, autonomous scheduling, and saved profiles.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(onClick = onNewScan) {
                        Text("Create scan profile")
                    }
                }
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
                title = "Service detection (-sV)",
                checked = state.enableServiceDetection,
                onCheckedChange = onServiceDetectionChanged,
            )
            SettingSwitchRow(
                title = "Default scripts (-sC)",
                checked = state.enableDefaultScripts,
                onCheckedChange = onDefaultScriptsChanged,
            )
            SettingSwitchRow(
                title = "OS detection (-O)",
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
private fun HistoryScreen(
    runs: List<ScanRunSummary>,
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
            Text(text = "Execution history", style = MaterialTheme.typography.headlineSmall)
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
    onBaseUrlChanged: (String) -> Unit,
    onTokenChanged: (String) -> Unit,
    onSave: () -> Unit,
    onRefreshCapabilities: () -> Unit,
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
        Text(text = "Remote executor settings", style = MaterialTheme.typography.headlineSmall)
        Text(
            text = "Remote mode provides the honest path to broader Nmap functionality on modern non-root Android. The bearer token is stored encrypted with Android Keystore.",
        )
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
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onSave) {
                Text("Save settings")
            }
            Button(onClick = onRefreshCapabilities) {
                Text(if (capabilityState.loading) "Checking..." else "Refresh capabilities")
            }
        }
        capabilityState.capabilities?.let { capabilities ->
            Card {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Remote capability report", style = MaterialTheme.typography.titleMedium)
                    Text(text = "nmap available: ${capabilities.nmapAvailable}")
                    Text(text = "ncat available: ${capabilities.ncatAvailable}")
                    Text(text = "nping available: ${capabilities.npingAvailable}")
                    Text(text = "privileged raw access: ${capabilities.privileged}")
                    Text(text = "requires authentication: ${capabilities.requiresAuthentication}")
                    Text(text = "max targets per request: ${capabilities.maxTargetsPerRequest}")
                    Text(text = "max arguments per request: ${capabilities.maxArgumentsPerRequest}")
                    Text(text = "captured output limit: ${capabilities.outputCaptureLimitBytes} bytes")
                    Text(text = "target policy: ${capabilities.targetPolicySummary}")
                    Text(text = capabilities.advisory)
                }
            }
        }
        capabilityState.error?.let { error ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text(text = error, modifier = Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onErrorContainer)
            }
        }
    }
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
            if (run.parsedSummary.portFindings.isNotEmpty()) {
                PreviewCard(
                    title = "Parsed findings",
                    body = run.parsedSummary.portFindings.joinToString(separator = "\n") { finding ->
                        buildString {
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
                    },
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

private fun formatTimestamp(epochMillis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(epochMillis))
