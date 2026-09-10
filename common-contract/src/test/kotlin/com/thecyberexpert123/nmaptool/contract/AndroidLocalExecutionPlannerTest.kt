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
    fun `nmap assessment blocks service detection and cidr targets`() {
        val assessment = AndroidLocalExecutionPlanner.assess(
            tool = ToolType.NMAP,
            targets = listOf("192.168.1.0/24"),
            arguments = listOf("-Pn", "-sV", "-F"),
            capabilities = capabilities,
        )

        assertFalse(assessment.supported)
        assertTrue(assessment.blockers.any { it.contains("discrete hosts only") })
        assertTrue(assessment.blockers.any { it.contains("does not support -sV") })
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
