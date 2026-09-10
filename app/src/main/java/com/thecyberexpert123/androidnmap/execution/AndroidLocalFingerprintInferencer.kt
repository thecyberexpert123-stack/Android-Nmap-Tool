package com.thecyberexpert123.androidnmap.execution

internal data class AndroidLocalPortObservation(
    val port: Int,
    val service: String,
    val details: String = "",
)

internal data class AndroidLocalFingerprintInference(
    val deviceType: String? = null,
    val osDetails: String,
    val evidence: List<String> = emptyList(),
    val familyGuessed: Boolean = false,
)

internal object AndroidLocalFingerprintInferencer {
    private enum class Family(val displayName: String) {
        WINDOWS("Windows-family"),
        LINUX_UNIX("Linux/Unix-family"),
        APPLE_DARWIN("Apple/Darwin-family"),
        ANDROID("Android/Linux-family"),
        EMBEDDED_NETWORK("Embedded/network-appliance family"),
    }

    private data class FamilyScore(
        var score: Int = 0,
        val evidence: LinkedHashSet<String> = linkedSetOf(),
    )

    fun infer(openPorts: List<AndroidLocalPortObservation>): AndroidLocalFingerprintInference {
        if (openPorts.isEmpty()) {
            return AndroidLocalFingerprintInference(
                osDetails = "android-local inference: insufficient evidence for a reliable OS-family guess",
                evidence = listOf("No open TCP endpoints were available for Android-local fingerprint inference."),
            )
        }

        val scores = Family.entries.associateWith { FamilyScore() }.toMutableMap()
        val normalizedPorts = openPorts.map { observation ->
            Triple(observation.port, observation.service.lowercase(), observation.details.lowercase())
        }
        val observedPortNumbers = normalizedPorts.map { it.first }.toSet()

        normalizedPorts.forEach { (port, service, details) ->
            if (port in setOf(135, 139, 445, 3389, 5985, 5986) || service in setOf("msrpc", "microsoft-ds", "ms-wbt-server")) {
                addEvidence(scores, Family.WINDOWS, 2, "Windows-associated management or SMB ports were observed.")
            }
            if (details.contains("microsoft") || details.contains("iis") || details.contains("microsoft-httpapi")) {
                addEvidence(scores, Family.WINDOWS, 3, "Service banners mention Microsoft/IIS components.")
            }

            if (port == 5555 || service == "adb" || details.contains("android debug bridge")) {
                addEvidence(scores, Family.ANDROID, 4, "Android-specific ADB/mobile indicators were observed.")
                addEvidence(scores, Family.LINUX_UNIX, 1, "Android indicators also imply a Linux-derived network stack.")
            }

            if (port in setOf(22, 111, 2049, 2375, 2376, 3306, 5432, 5672, 6379, 9092, 9300) ||
                service in setOf("ssh", "rpcbind", "nfs", "docker", "docker-ssl", "mysql", "postgresql", "amqp", "redis", "kafka", "elasticsearch-node")
            ) {
                addEvidence(scores, Family.LINUX_UNIX, 2, "Unix-style service mix was observed on open TCP ports.")
            }
            if (details.contains("openssh") || details.contains("dropbear") || details.contains("nginx") || details.contains("apache") || details.contains("lighttpd") || details.contains("caddy") || details.contains("gunicorn") || details.contains("uvicorn")) {
                addEvidence(scores, Family.LINUX_UNIX, 2, "Service banners resemble common Unix/Linux software stacks.")
            }

            if (port in setOf(548, 3689, 62078) || details.contains("darwin") || details.contains("apple") || details.contains("airplay") || details.contains("airtunes")) {
                addEvidence(scores, Family.APPLE_DARWIN, 3, "Apple/Darwin service fingerprints or ports were observed.")
            }

            if (details.contains("routeros") || details.contains("mikrotik") || details.contains("openwrt") || details.contains("uhttpd") || details.contains("mini_httpd") || details.contains("goahead") || details.contains("rompager") || details.contains("boa")) {
                addEvidence(scores, Family.EMBEDDED_NETWORK, 3, "Embedded or network-appliance HTTP/banner markers were observed.")
                addEvidence(scores, Family.LINUX_UNIX, 1, "Embedded appliance banners often ride on Linux/Unix-like stacks.")
            }
        }

        if (23 in observedPortNumbers && observedPortNumbers.any { it in setOf(80, 443, 8080, 8443) }) {
            addEvidence(scores, Family.EMBEDDED_NETWORK, 1, "Telnet plus web-management ports suggest an embedded or appliance-style target.")
        }
        if (observedPortNumbers.containsAll(setOf(135, 445)) || observedPortNumbers.containsAll(setOf(445, 3389))) {
            addEvidence(scores, Family.WINDOWS, 2, "The open-port combination resembles a Windows workstation/server footprint.")
        }
        if (observedPortNumbers.contains(22) && observedPortNumbers.any { it in setOf(80, 443, 3306, 5432, 6379, 6443) }) {
            addEvidence(scores, Family.LINUX_UNIX, 1, "SSH combined with web/database/service ports suggests a Unix-like host or server.")
        }
        if (observedPortNumbers.contains(62078) || (observedPortNumbers.contains(548) && observedPortNumbers.contains(5353))) {
            addEvidence(scores, Family.APPLE_DARWIN, 2, "The observed port mix is consistent with Apple device or service exposure.")
        }

        val ranked = scores.entries
            .sortedWith(
                compareByDescending<Map.Entry<Family, FamilyScore>> { it.value.score }
                    .thenBy { it.key.ordinal },
            )
        val best = ranked.firstOrNull()
        val runnerUp = ranked.getOrNull(1)
        val bestScore = best?.value?.score ?: 0
        val secondScore = runnerUp?.value?.score ?: 0

        if (best == null || bestScore < 2 || bestScore == secondScore) {
            val evidence = ranked
                .flatMap { (_, score) -> score.evidence }
                .distinct()
                .take(3)
                .ifEmpty {
                    listOf("Only generic open-port evidence was available locally.")
                }
            return AndroidLocalFingerprintInference(
                osDetails = "android-local inference: insufficient evidence for a reliable OS-family guess",
                evidence = evidence + "Try -sV for stronger local evidence, or use a delegated executor for real Nmap OS detection.",
            )
        }

        val confidence = when {
            bestScore >= 6 && bestScore - secondScore >= 2 -> "high"
            bestScore >= 4 -> "medium"
            else -> "low"
        }
        val deviceType = inferDeviceType(best.key, observedPortNumbers)
        val evidence = best.value.evidence.take(3)
        val osDetails = "android-local inference: likely ${best.key.displayName} (confidence: $confidence)"
        return AndroidLocalFingerprintInference(
            deviceType = deviceType,
            osDetails = osDetails,
            evidence = evidence,
            familyGuessed = true,
        )
    }

    private fun addEvidence(
        scores: MutableMap<Family, FamilyScore>,
        family: Family,
        points: Int,
        evidence: String,
    ) {
        val score = scores.getValue(family)
        score.score += points
        score.evidence += evidence
    }

    private fun inferDeviceType(
        family: Family,
        observedPortNumbers: Set<Int>,
    ): String = when (family) {
        Family.WINDOWS -> if (observedPortNumbers.any { it in setOf(1433, 3389, 5985, 5986) }) {
            "general-purpose host or server"
        } else {
            "general-purpose host"
        }

        Family.LINUX_UNIX -> if (observedPortNumbers.any { it in setOf(3306, 5432, 5672, 6379, 9092, 9200, 9300) }) {
            "server"
        } else {
            "general-purpose host or server"
        }

        Family.APPLE_DARWIN -> if (62078 in observedPortNumbers) {
            "mobile or desktop Apple device"
        } else {
            "Apple workstation or media device"
        }

        Family.ANDROID -> "mobile or Android-based device"
        Family.EMBEDDED_NETWORK -> "network appliance or embedded device"
    }
}
