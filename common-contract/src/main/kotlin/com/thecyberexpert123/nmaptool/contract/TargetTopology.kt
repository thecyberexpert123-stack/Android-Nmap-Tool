package com.thecyberexpert123.nmaptool.contract

import kotlinx.serialization.Serializable

@Serializable
enum class TargetTopologyScope {
    PRIVATE_LAN,
    LINK_LOCAL,
    LOOPBACK,
    CARRIER_GRADE_NAT,
    PUBLIC_INTERNET,
    HOSTNAME_OR_UNRESOLVED,
    UNKNOWN,
}

private val privateLikeTargetScopes = setOf(
    TargetTopologyScope.PRIVATE_LAN,
    TargetTopologyScope.LINK_LOCAL,
    TargetTopologyScope.LOOPBACK,
    TargetTopologyScope.CARRIER_GRADE_NAT,
)

val allTargetTopologyScopes: List<TargetTopologyScope> = TargetTopologyScope.entries.toList()

data class TargetTopologySummary(
    val scopes: Set<TargetTopologyScope>,
    val privateLikeOnly: Boolean,
    val containsPublicInternet: Boolean,
    val containsUnknownOrHostname: Boolean,
)

object TargetTopologyClassifier {
    fun classify(target: String): TargetTopologyScope {
        val host = extractHostToken(target)
        if (host.isBlank()) {
            return TargetTopologyScope.UNKNOWN
        }

        parseIpv4(host)?.let { octets ->
            val first = octets[0]
            val second = octets[1]
            return when {
                first == 10 -> TargetTopologyScope.PRIVATE_LAN
                first == 172 && second in 16..31 -> TargetTopologyScope.PRIVATE_LAN
                first == 192 && second == 168 -> TargetTopologyScope.PRIVATE_LAN
                first == 169 && second == 254 -> TargetTopologyScope.LINK_LOCAL
                first == 127 -> TargetTopologyScope.LOOPBACK
                first == 100 && second in 64..127 -> TargetTopologyScope.CARRIER_GRADE_NAT
                else -> TargetTopologyScope.PUBLIC_INTERNET
            }
        }

        if (looksLikeIpv6Literal(host)) {
            val normalized = host.lowercase()
            return when {
                normalized == "::1" -> TargetTopologyScope.LOOPBACK
                normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb") -> TargetTopologyScope.LINK_LOCAL
                normalized.startsWith("fc") || normalized.startsWith("fd") -> TargetTopologyScope.PRIVATE_LAN
                else -> TargetTopologyScope.PUBLIC_INTERNET
            }
        }

        return TargetTopologyScope.HOSTNAME_OR_UNRESOLVED
    }

    fun summarize(targets: List<String>): TargetTopologySummary {
        val scopes = targets.map(::classify).toSet()
        return TargetTopologySummary(
            scopes = scopes,
            privateLikeOnly = scopes.isNotEmpty() && scopes.all { it in privateLikeTargetScopes || it == TargetTopologyScope.HOSTNAME_OR_UNRESOLVED },
            containsPublicInternet = TargetTopologyScope.PUBLIC_INTERNET in scopes,
            containsUnknownOrHostname = scopes.any { it == TargetTopologyScope.HOSTNAME_OR_UNRESOLVED || it == TargetTopologyScope.UNKNOWN },
        )
    }

    fun isPrivateLike(scope: TargetTopologyScope): Boolean = scope in privateLikeTargetScopes

    private fun extractHostToken(rawTarget: String): String {
        val target = rawTarget.trim()
        if (target.isBlank()) {
            return ""
        }
        val withoutCidr = target.substringBefore('/')
        if (withoutCidr.startsWith("[") && withoutCidr.contains(']')) {
            return withoutCidr.substringAfter('[').substringBefore(']')
        }
        val lastColon = withoutCidr.lastIndexOf(':')
        val firstColon = withoutCidr.indexOf(':')
        return if (lastColon > 0 && firstColon == lastColon) {
            val host = withoutCidr.substring(0, lastColon)
            val portCandidate = withoutCidr.substring(lastColon + 1)
            if (portCandidate.all(Char::isDigit)) host else withoutCidr
        } else {
            withoutCidr
        }
    }

    private fun parseIpv4(host: String): List<Int>? {
        val parts = host.split('.')
        if (parts.size != 4) {
            return null
        }
        val octets = parts.map { it.toIntOrNull() ?: return null }
        return octets.takeIf { octetValues -> octetValues.all { it in 0..255 } }
    }

    private fun looksLikeIpv6Literal(host: String): Boolean {
        if (!host.contains(':')) {
            return false
        }
        return host.all { character ->
            character.isDigit() || character.lowercaseChar() in 'a'..'f' || character == ':' || character == '.'
        }
    }
}

data class DelegatedExecutorRoutingCandidate(
    val id: String,
    val label: String,
    val configured: Boolean,
    val kind: ExecutorNodeKind,
    val allowedTargetScopes: Set<TargetTopologyScope> = allTargetTopologyScopes.toSet(),
    val capabilitiesFresh: Boolean = false,
)

data class DelegatedExecutorRoutingSelection(
    val candidateId: String,
    val label: String,
    val targetSummary: TargetTopologySummary,
    val reason: String,
)

object DelegatedExecutorRoutingAdvisor {
    fun select(
        targets: List<String>,
        candidates: List<DelegatedExecutorRoutingCandidate>,
    ): DelegatedExecutorRoutingSelection? {
        val configuredCandidates = candidates.filter { it.configured }
        if (configuredCandidates.isEmpty()) {
            return null
        }
        val targetSummary = TargetTopologyClassifier.summarize(targets)
        val ranked = configuredCandidates.mapNotNull { candidate ->
            scoreCandidate(candidate, targetSummary)?.let { score -> candidate to score }
        }.sortedByDescending { it.second }
        val selected = ranked.firstOrNull()?.first ?: return null
        return DelegatedExecutorRoutingSelection(
            candidateId = selected.id,
            label = selected.label,
            targetSummary = targetSummary,
            reason = when {
                targetSummary.privateLikeOnly && selected.kind == ExecutorNodeKind.LAN_AGENT -> {
                    "Selected the delegated LAN agent because the target set is private-topology oriented."
                }
                targetSummary.containsPublicInternet && selected.kind == ExecutorNodeKind.REMOTE_NMAP -> {
                    "Selected the general delegated executor because the target set includes public-internet addressing."
                }
                selected.capabilitiesFresh -> {
                    "Selected the delegated executor whose verified target-scope policy best matches the current targets."
                }
                else -> {
                    "Selected the best available delegated executor using configured role and target-topology hints."
                }
            },
        )
    }

    private fun scoreCandidate(
        candidate: DelegatedExecutorRoutingCandidate,
        targetSummary: TargetTopologySummary,
    ): Int? {
        if (targetSummary.scopes.any { it !in candidate.allowedTargetScopes }) {
            return null
        }
        var score = 0
        if (candidate.capabilitiesFresh) {
            score += 20
        }
        if (targetSummary.privateLikeOnly) {
            score += when (candidate.kind) {
                ExecutorNodeKind.LAN_AGENT -> 60
                ExecutorNodeKind.REMOTE_NMAP -> 25
                ExecutorNodeKind.ANDROID_LOCAL, ExecutorNodeKind.UNKNOWN -> 10
            }
        } else if (targetSummary.containsPublicInternet) {
            score += when (candidate.kind) {
                ExecutorNodeKind.REMOTE_NMAP -> 50
                ExecutorNodeKind.LAN_AGENT -> -20
                ExecutorNodeKind.ANDROID_LOCAL, ExecutorNodeKind.UNKNOWN -> 0
            }
        } else {
            score += when (candidate.kind) {
                ExecutorNodeKind.REMOTE_NMAP -> 30
                ExecutorNodeKind.LAN_AGENT -> 30
                ExecutorNodeKind.ANDROID_LOCAL, ExecutorNodeKind.UNKNOWN -> 5
            }
        }
        if (targetSummary.containsUnknownOrHostname && TargetTopologyScope.HOSTNAME_OR_UNRESOLVED in candidate.allowedTargetScopes) {
            score += 10
        }
        return score
    }
}
