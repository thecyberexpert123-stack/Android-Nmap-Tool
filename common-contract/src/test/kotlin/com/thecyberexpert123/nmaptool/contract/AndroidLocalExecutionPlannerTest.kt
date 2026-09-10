package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AndroidLocalExecutionPlannerTest {
    private val capabilities = AndroidLocalCapabilities(
        available = true,
        networkAvailable = true,
        activeNetworkSummary = "Wi-Fi — validated internet",
        supportsServiceDetection = true,
        supportsAndroidFingerprinting = true,
        maxServiceDetectionsPerRun = 32,
    )

    @Test
    fun `nmap plan supports explicit tcp port ranges`() {
        val result = AndroidLocalExecutionPlanner.createNmapPlan(
            arguments = listOf("-Pn", "-p", "22,80,443,8000-8002"),
            capabilities = capabilities,
        )

        assertTrue(result.isValid)
        assertEquals(listOf(22, 80, 443, 8000, 8001, 8002), result.value?.ports)
        assertEquals(true, result.value?.skipHostDiscovery)
    }

    @Test
    fun `nmap assessment allows curated service detection and fingerprint inference but still blocks cidr targets`() {
        val assessment = AndroidLocalExecutionPlanner.assess(
            tool = ToolType.NMAP,
            targets = listOf("192.168.1.0/24"),
            arguments = listOf("-Pn", "-sV", "-O", "-F"),
            capabilities = capabilities,
        )

        assertFalse(assessment.supported)
        assertTrue(assessment.blockers.any { it.contains("discrete hosts only") })
        assertTrue(assessment.warnings.any { it.contains("curated protocol detection") })
        assertTrue(assessment.warnings.any { it.contains("evidence-based OS-family inference") })
        assertTrue(assessment.notes.any { it.contains("up to 32 open TCP endpoints") })
        assertTrue(assessment.notes.any { it.contains("Combining -O with -sV improves Android-local fingerprint evidence") })
        assertTrue(assessment.preferDelegatedWhenAvailable)
    }

    @Test
    fun `nmap plan enables curated local service detection and fingerprint inference when supported`() {
        val result = AndroidLocalExecutionPlanner.createNmapPlan(
            arguments = listOf("-Pn", "-sV", "-O", "-F", "-T4"),
            capabilities = capabilities,
        )

        assertTrue(result.isValid)
        assertEquals(true, result.value?.enableServiceDetection)
        assertEquals(true, result.value?.enableFingerprintInference)
        assertEquals(true, result.value?.usedCuratedPortCatalog)
        assertEquals(100, result.value?.ports?.size)
        assertEquals(1_000, result.value?.connectTimeoutMillis)
        assertEquals(1_000, result.value?.serviceReadTimeoutMillis)
    }

    @Test
    fun `nmap plan blocks service detection and fingerprint inference when runtime support is unavailable`() {
        val result = AndroidLocalExecutionPlanner.createNmapPlan(
            arguments = listOf("-Pn", "-sV", "-O", "-p", "443"),
            capabilities = capabilities.copy(
                supportsServiceDetection = false,
                supportsAndroidFingerprinting = false,
            ),
        )

        assertFalse(result.isValid)
        assertTrue(result.issues.any { it.message.contains("-sV requires a delegated executor") })
        assertTrue(result.issues.any { it.message.contains("-O requires a delegated executor") })
    }

    @Test
    fun `nping plan supports tcp connect with bounded count`() {
        val result = AndroidLocalExecutionPlanner.createNpingPlan(
            targets = listOf("scanme.nmap.org:443"),
            arguments = listOf("--tcp-connect", "-c", "3", "--delay", "250ms"),
            capabilities = capabilities,
        )

        assertTrue(result.isValid)
        assertEquals(AndroidLocalNpingMode.TCP_CONNECT, result.value?.mode)
        assertEquals(443, result.value?.port)
        assertEquals(3, result.value?.count)
        assertEquals(250L, result.value?.delayMillis)
    }

    @Test
    fun `nping raw tcp mode is blocked locally`() {
        val result = AndroidLocalExecutionPlanner.createNpingPlan(
            targets = listOf("scanme.nmap.org:80"),
            arguments = listOf("--tcp"),
            capabilities = capabilities,
        )

        assertFalse(result.isValid)
        assertTrue(result.issues.any { it.message.contains("raw packet access") })
    }

    @Test
    fun `ncat requires explicit host port target`() {
        val result = AndroidLocalExecutionPlanner.createNcatPlan(
            targets = listOf("scanme.nmap.org"),
            arguments = listOf("-v"),
        )

        assertFalse(result.isValid)
        assertTrue(result.issues.any { it.message.contains("requires the target to include a TCP port") })
    }
}
