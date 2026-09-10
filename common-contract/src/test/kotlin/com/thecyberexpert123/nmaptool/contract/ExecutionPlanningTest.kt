package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ExecutionPlanningTest {
    @Test
    fun `execution route advisor prefers delegated route for auto when local support is bounded`() {
        assertEquals(
            ExecutionRoute.REMOTE,
            ExecutionRouteAdvisor.select(
                executionPreference = ExecutionPreference.AUTO,
                remoteConfigured = true,
                localSupported = true,
                preferDelegatedWhenAvailable = true,
            ),
        )
        assertEquals(
            ExecutionRoute.LOCAL,
            ExecutionRouteAdvisor.select(
                executionPreference = ExecutionPreference.AUTO,
                remoteConfigured = false,
                localSupported = true,
                preferDelegatedWhenAvailable = true,
            ),
        )
    }

    private val localCapabilities = AndroidLocalCapabilities(
        available = true,
        networkAvailable = true,
        activeNetworkSummary = "Wi-Fi — validated internet",
        supportsServiceDetection = true,
        supportsAndroidFingerprinting = true,
        maxServiceDetectionsPerRun = 32,
    )

    @Test
    fun `auto mode recommends delegated execution when local service and fingerprint features are only bounded local fallbacks`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
            targets = listOf("scanme.nmap.org"),
            executionPreference = ExecutionPreference.AUTO,
            arguments = listOf("-Pn", "-sV", "-O", "-F"),
            remoteConfigured = true,
            remoteCapabilities = RemoteCapabilitiesResponse(
                nmapAvailable = true,
                ncatAvailable = true,
                npingAvailable = true,
                privileged = true,
                requiresAuthentication = true,
                maxTargetsPerRequest = 64,
                maxArgumentsPerRequest = 128,
                outputCaptureLimitBytes = 262_144,
                targetPolicySummary = "No target regex restriction configured.",
                advisory = "Remote execution is preferred.",
                supportsStructuredNmapXml = true,
                executorLabel = "lab-a",
                nmapVersion = "Nmap 7.95",
            ),
            remoteCapabilitiesStale = false,
            localCapabilities = localCapabilities,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.READY, guidance.status)
        assertEquals(ExecutionRoute.REMOTE, guidance.likelyRoute)
        assertEquals("lab-a", guidance.likelyExecutorTitle)
        assertTrue(guidance.summary.contains("delegated executor"))
        assertTrue(guidance.notes.any { it.contains("structured Nmap XML") })
        assertTrue(guidance.notes.any { it.contains("lab-a") })
        assertTrue(guidance.notes.any { it.contains("Local route limitation") })
        assertTrue(guidance.notes.any { it.contains("prefer the delegated executor") })
    }

    @Test
    fun `auto mode keeps bounded local service detection and fingerprint inference when no delegated executor exists`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
            targets = listOf("scanme.nmap.org"),
            executionPreference = ExecutionPreference.AUTO,
            arguments = listOf("-Pn", "-sV", "-O", "-F"),
            remoteConfigured = false,
            remoteCapabilities = null,
            remoteCapabilitiesStale = false,
            localCapabilities = localCapabilities,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.CAUTION, guidance.status)
        assertEquals(ExecutionRoute.LOCAL, guidance.likelyRoute)
        assertEquals("Android local executor", guidance.likelyExecutorTitle)
        assertTrue(guidance.warnings.any { it.contains("not full Nmap version-detection parity") })
        assertTrue(guidance.warnings.any { it.contains("not Nmap TCP/IP stack fingerprinting parity") })
        assertTrue(guidance.notes.any { it.contains("phase-C baseline") })
    }

    @Test
    fun `auto mode blocks when neither local nor remote execution is viable`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
            targets = listOf("scanme.nmap.org/24"),
            executionPreference = ExecutionPreference.AUTO,
            arguments = listOf("-Pn"),
            remoteConfigured = false,
            remoteCapabilities = null,
            remoteCapabilitiesStale = false,
            localCapabilities = localCapabilities,
            scheduleEnabled = true,
        )

        assertEquals(ExecutionGuidanceStatus.BLOCKED, guidance.status)
        assertNull(guidance.likelyRoute)
        assertTrue(guidance.blockers.any { it.contains("no viable route") })
        assertTrue(guidance.blockers.any { it.contains("discrete hosts only") })
        assertTrue(guidance.notes.any { it.contains("WorkManager") })
    }

    @Test
    fun `local only quick tcp profile is ready with cautionary notes`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
            targets = listOf("scanme.nmap.org"),
            executionPreference = ExecutionPreference.LOCAL_ONLY,
            arguments = listOf("-Pn", "-F"),
            remoteConfigured = false,
            remoteCapabilities = null,
            remoteCapabilitiesStale = false,
            localCapabilities = localCapabilities,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.CAUTION, guidance.status)
        assertEquals(ExecutionRoute.LOCAL, guidance.likelyRoute)
        assertEquals("Android local executor", guidance.likelyExecutorTitle)
        assertTrue(guidance.summary.contains("run locally"))
        assertTrue(guidance.warnings.any { it.contains("curated fast TCP port catalog") })
        assertTrue(guidance.notes.any { it.contains("phase-C baseline") })
    }

    @Test
    fun `stale capability data yields caution rather than ready`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NCAT,
            targets = listOf("scanme.nmap.org:80"),
            executionPreference = ExecutionPreference.REMOTE_ONLY,
            arguments = listOf("-v"),
            remoteConfigured = true,
            remoteCapabilities = RemoteCapabilitiesResponse(
                nmapAvailable = true,
                ncatAvailable = true,
                npingAvailable = true,
                privileged = false,
                requiresAuthentication = false,
                maxTargetsPerRequest = 64,
                maxArgumentsPerRequest = 128,
                outputCaptureLimitBytes = 262_144,
                targetPolicySummary = "No target regex restriction configured.",
                advisory = "Remote execution is preferred.",
                executorLabel = "stale-lab",
            ),
            remoteCapabilitiesStale = true,
            localCapabilities = localCapabilities,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.CAUTION, guidance.status)
        assertEquals(ExecutionRoute.REMOTE, guidance.likelyRoute)
        assertEquals("stale-lab", guidance.likelyExecutorTitle)
        assertTrue(guidance.warnings.any { it.contains("stale") })
    }

    @Test
    fun `privileged nmap options warn when executor is not privileged`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
            targets = listOf("scanme.nmap.org"),
            executionPreference = ExecutionPreference.REMOTE_ONLY,
            arguments = listOf("-sS", "-Pn"),
            remoteConfigured = true,
            remoteCapabilities = RemoteCapabilitiesResponse(
                nmapAvailable = true,
                ncatAvailable = true,
                npingAvailable = true,
                privileged = false,
                requiresAuthentication = false,
                maxTargetsPerRequest = 64,
                maxArgumentsPerRequest = 128,
                outputCaptureLimitBytes = 262_144,
                targetPolicySummary = "No target regex restriction configured.",
                advisory = "Remote execution is preferred.",
                supportsStructuredNmapXml = true,
            ),
            remoteCapabilitiesStale = false,
            localCapabilities = localCapabilities,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.CAUTION, guidance.status)
        assertTrue(guidance.warnings.any { it.contains("privileged/raw access") })
        assertTrue(guidance.warnings.any { it.contains("-sS SYN scan") })
    }

    @Test
    fun `verified remote tool absence blocks remote execution`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NPING,
            targets = listOf("scanme.nmap.org"),
            executionPreference = ExecutionPreference.REMOTE_ONLY,
            arguments = listOf("--tcp-connect"),
            remoteConfigured = true,
            remoteCapabilities = RemoteCapabilitiesResponse(
                nmapAvailable = true,
                ncatAvailable = true,
                npingAvailable = false,
                privileged = false,
                requiresAuthentication = false,
                maxTargetsPerRequest = 64,
                maxArgumentsPerRequest = 128,
                outputCaptureLimitBytes = 262_144,
                targetPolicySummary = "No target regex restriction configured.",
                advisory = "Remote execution is preferred.",
            ),
            remoteCapabilitiesStale = false,
            localCapabilities = localCapabilities,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.BLOCKED, guidance.status)
        assertEquals(ExecutionRoute.REMOTE, guidance.likelyRoute)
        assertTrue(guidance.blockers.any { it.contains("does not currently report nping as available") })
    }
}
