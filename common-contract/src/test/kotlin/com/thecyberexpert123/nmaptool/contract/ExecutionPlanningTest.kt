package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ExecutionPlanningTest {
    @Test
    fun `auto mode recommends remote execution when local execution is unavailable but remote capabilities are verified`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
            executionPreference = ExecutionPreference.AUTO,
            arguments = listOf("-Pn", "-sV"),
            remoteConfigured = true,
            remoteCapabilities = RemoteCapabilitiesResponse(
                nmapAvailable = true,
                ncatAvailable = true,
                npingAvailable = true,
                privileged = false,
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
            localExecutionSupported = false,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.READY, guidance.status)
        assertEquals(ExecutionRoute.REMOTE, guidance.likelyRoute)
        assertTrue(guidance.summary.contains("remote executor"))
        assertTrue(guidance.notes.any { it.contains("structured Nmap XML") })
        assertTrue(guidance.notes.any { it.contains("lab-a") })
    }

    @Test
    fun `auto mode blocks when neither local nor remote execution is viable`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
            executionPreference = ExecutionPreference.AUTO,
            arguments = listOf("-Pn"),
            remoteConfigured = false,
            remoteCapabilities = null,
            remoteCapabilitiesStale = false,
            localExecutionSupported = false,
            scheduleEnabled = true,
        )

        assertEquals(ExecutionGuidanceStatus.BLOCKED, guidance.status)
        assertNull(guidance.likelyRoute)
        assertTrue(guidance.blockers.any { it.contains("no viable route") })
        assertTrue(guidance.notes.any { it.contains("WorkManager") })
    }

    @Test
    fun `stale capability data yields caution rather than ready`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NCAT,
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
            localExecutionSupported = false,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.CAUTION, guidance.status)
        assertEquals(ExecutionRoute.REMOTE, guidance.likelyRoute)
        assertTrue(guidance.warnings.any { it.contains("stale") })
    }

    @Test
    fun `privileged nmap options warn when executor is not privileged`() {
        val guidance = ExecutionGuidanceAdvisor.analyze(
            tool = ToolType.NMAP,
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
            localExecutionSupported = false,
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
            localExecutionSupported = false,
            scheduleEnabled = false,
        )

        assertEquals(ExecutionGuidanceStatus.BLOCKED, guidance.status)
        assertEquals(ExecutionRoute.REMOTE, guidance.likelyRoute)
        assertTrue(guidance.blockers.any { it.contains("does not currently report nping as available") })
    }
}
