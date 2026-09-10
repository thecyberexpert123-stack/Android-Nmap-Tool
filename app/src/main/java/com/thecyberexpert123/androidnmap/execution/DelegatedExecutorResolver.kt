package com.thecyberexpert123.androidnmap.execution

import com.thecyberexpert123.androidnmap.settings.DelegatedExecutorSlot
import com.thecyberexpert123.androidnmap.settings.RemoteEndpointSettings
import com.thecyberexpert123.nmaptool.contract.DelegatedExecutorRoutingAdvisor
import com.thecyberexpert123.nmaptool.contract.DelegatedExecutorRoutingCandidate
import com.thecyberexpert123.nmaptool.contract.ExecutorNodeKind
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import com.thecyberexpert123.nmaptool.contract.TargetTopologyClassifier
import com.thecyberexpert123.nmaptool.contract.TargetTopologyScope
import com.thecyberexpert123.nmaptool.contract.allTargetTopologyScopes

data class DelegatedExecutorEndpointRecord(
    val slot: DelegatedExecutorSlot,
    val label: String,
    val settings: RemoteEndpointSettings,
    val fallbackKind: ExecutorNodeKind,
    val capabilities: RemoteCapabilitiesResponse? = null,
    val capabilitiesCheckedAtEpochMillis: Long? = null,
    val capabilitiesStale: Boolean = false,
)

data class DelegatedExecutorSelection(
    val slot: DelegatedExecutorSlot,
    val label: String,
    val settings: RemoteEndpointSettings,
    val capabilities: RemoteCapabilitiesResponse?,
    val capabilitiesCheckedAtEpochMillis: Long?,
    val capabilitiesStale: Boolean,
    val routingReason: String,
)

object DelegatedExecutorResolver {
    fun select(
        targets: List<String>,
        records: List<DelegatedExecutorEndpointRecord>,
    ): DelegatedExecutorSelection? {
        val selection = DelegatedExecutorRoutingAdvisor.select(
            targets = targets,
            candidates = records.map(::toRoutingCandidate),
        ) ?: return null
        val record = records.firstOrNull { it.slot.name == selection.candidateId } ?: return null
        return DelegatedExecutorSelection(
            slot = record.slot,
            label = record.label,
            settings = record.settings,
            capabilities = record.capabilities,
            capabilitiesCheckedAtEpochMillis = record.capabilitiesCheckedAtEpochMillis,
            capabilitiesStale = record.capabilitiesStale,
            routingReason = selection.reason,
        )
    }

    fun incompatibilityMessage(
        targets: List<String>,
        records: List<DelegatedExecutorEndpointRecord>,
    ): String? {
        val configured = records.filter { it.settings.baseUrl.isNotBlank() }
        if (configured.isEmpty() || select(targets, records) != null) {
            return null
        }
        val scopeSummary = TargetTopologyClassifier.summarize(targets)
        val scopeLabel = if (scopeSummary.scopes.isEmpty()) {
            "no resolved target scopes"
        } else {
            scopeSummary.scopes.sortedBy { it.ordinal }.joinToString(separator = ", ") { it.name }
        }
        return "Configured delegated executors do not currently match the target topology/policy for: $scopeLabel."
    }

    private fun toRoutingCandidate(record: DelegatedExecutorEndpointRecord): DelegatedExecutorRoutingCandidate =
        DelegatedExecutorRoutingCandidate(
            id = record.slot.name,
            label = record.label,
            configured = record.settings.baseUrl.isNotBlank(),
            kind = record.capabilities?.executorNodeKind ?: record.fallbackKind,
            allowedTargetScopes = record.capabilities?.allowedTargetScopes?.ifEmpty { allTargetTopologyScopes.toSet() }
                ?: defaultTargetScopesForKind(record.fallbackKind),
            capabilitiesFresh = record.capabilities != null && !record.capabilitiesStale,
        )

    fun defaultTargetScopesForKind(kind: ExecutorNodeKind): Set<TargetTopologyScope> = when (kind) {
        ExecutorNodeKind.LAN_AGENT -> setOf(
            TargetTopologyScope.PRIVATE_LAN,
            TargetTopologyScope.LINK_LOCAL,
            TargetTopologyScope.LOOPBACK,
            TargetTopologyScope.CARRIER_GRADE_NAT,
            TargetTopologyScope.HOSTNAME_OR_UNRESOLVED,
            TargetTopologyScope.UNKNOWN,
        )

        ExecutorNodeKind.REMOTE_NMAP,
        ExecutorNodeKind.ANDROID_LOCAL,
        ExecutorNodeKind.UNKNOWN,
        -> allTargetTopologyScopes.toSet()
    }
}
