package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ExecutorCapabilitiesTest {
    @Test
    fun `android local capabilities map to an on-device executor profile`() {
        val profile = AndroidLocalCapabilities(
            available = true,
            networkAvailable = true,
            activeNetworkSummary = "Wi-Fi — validated internet",
            supportsTcpConnectScan = true,
            supportsUdpDatagramProbes = true,
            supportsServiceDetection = true,
            supportsAndroidFingerprinting = true,
            maxTargetsPerRun = 16,
            maxPortsPerTarget = 256,
            maxTotalProbes = 1024,
            maxServiceDetectionsPerRun = 32,
        ).toExecutorCapabilityProfile()

        assertEquals("android-local", profile.id)
        assertEquals(ExecutorNodeKind.ANDROID_LOCAL, profile.kind)
        assertEquals(ExecutorTransportKind.ON_DEVICE, profile.transport)
        assertTrue(profile.capabilities.any {
            it.id == ExecutionCapabilityId.TCP_CONNECT_SCAN && it.level == ExecutionCapabilityLevel.SUPPORTED
        })
        assertTrue(profile.capabilities.any {
            it.id == ExecutionCapabilityId.CURATED_SERVICE_DETECTION &&
                it.level == ExecutionCapabilityLevel.LIMITED &&
                it.summary.contains("32 open TCP endpoints per run")
        })
        assertTrue(profile.capabilities.any {
            it.id == ExecutionCapabilityId.ANDROID_FINGERPRINT_INFERENCE &&
                it.level == ExecutionCapabilityLevel.LIMITED &&
                it.summary.contains("not raw TCP/IP stack fingerprinting parity")
        })
        assertTrue(profile.capabilities.any {
            it.id == ExecutionCapabilityId.RAW_PACKET_PROBES && it.level == ExecutionCapabilityLevel.UNSUPPORTED
        })
    }

    @Test
    fun `remote capabilities map to a delegated executor profile`() {
        val response = RemoteCapabilitiesResponse(
            nmapAvailable = true,
            ncatAvailable = true,
            npingAvailable = true,
            privileged = true,
            requiresAuthentication = true,
            maxTargetsPerRequest = 64,
            maxArgumentsPerRequest = 128,
            outputCaptureLimitBytes = 262_144,
            targetPolicySummary = "Targets must match policy.",
            advisory = "Delegated execution available.",
            supportsStructuredNmapXml = true,
            executorLabel = "lab-east-1",
            auditLoggingEnabled = true,
            maxConcurrentExecutions = 2,
        )

        val profile = response.toExecutorCapabilityProfile()

        assertEquals(ExecutorNodeKind.REMOTE_NMAP, profile.kind)
        assertEquals(ExecutorTransportKind.HTTPS, profile.transport)
        assertEquals("lab-east-1", profile.label)
        assertEquals(2, profile.maxConcurrentExecutions)
        assertNotNull(profile.capabilities.firstOrNull { it.id == ExecutionCapabilityId.NMAP_OS_DETECTION })
        assertTrue(profile.capabilities.any {
            it.id == ExecutionCapabilityId.STRUCTURED_NMAP_XML && it.level == ExecutionCapabilityLevel.SUPPORTED
        })
        assertTrue(profile.capabilities.any {
            it.id == ExecutionCapabilityId.AUDIT_LOGGING && it.level == ExecutionCapabilityLevel.SUPPORTED
        })
    }
}
