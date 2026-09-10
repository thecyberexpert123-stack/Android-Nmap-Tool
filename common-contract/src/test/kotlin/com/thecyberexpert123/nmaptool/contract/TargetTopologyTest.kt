package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TargetTopologyTest {
    @Test
    fun `classifier detects private and public topology scopes`() {
        assertEquals(TargetTopologyScope.PRIVATE_LAN, TargetTopologyClassifier.classify("192.168.1.10"))
        assertEquals(TargetTopologyScope.LINK_LOCAL, TargetTopologyClassifier.classify("169.254.10.20"))
        assertEquals(TargetTopologyScope.LOOPBACK, TargetTopologyClassifier.classify("127.0.0.1"))
        assertEquals(TargetTopologyScope.CARRIER_GRADE_NAT, TargetTopologyClassifier.classify("100.100.10.20"))
        assertEquals(TargetTopologyScope.PUBLIC_INTERNET, TargetTopologyClassifier.classify("8.8.8.8"))
        assertEquals(TargetTopologyScope.HOSTNAME_OR_UNRESOLVED, TargetTopologyClassifier.classify("scanme.nmap.org"))
    }

    @Test
    fun `classifier tolerates host port and cidr forms`() {
        assertEquals(TargetTopologyScope.PRIVATE_LAN, TargetTopologyClassifier.classify("192.168.0.5:443"))
        assertEquals(TargetTopologyScope.PRIVATE_LAN, TargetTopologyClassifier.classify("192.168.0.0/24"))
        assertEquals(TargetTopologyScope.LOOPBACK, TargetTopologyClassifier.classify("[::1]:80"))
        assertEquals(TargetTopologyScope.LINK_LOCAL, TargetTopologyClassifier.classify("fe80::1"))
    }

    @Test
    fun `routing advisor prefers lan agent for private topology targets`() {
        val selection = DelegatedExecutorRoutingAdvisor.select(
            targets = listOf("192.168.1.25"),
            candidates = listOf(
                DelegatedExecutorRoutingCandidate(
                    id = "primary",
                    label = "Primary delegated executor",
                    configured = true,
                    kind = ExecutorNodeKind.REMOTE_NMAP,
                    capabilitiesFresh = false,
                ),
                DelegatedExecutorRoutingCandidate(
                    id = "lan",
                    label = "LAN agent",
                    configured = true,
                    kind = ExecutorNodeKind.LAN_AGENT,
                    allowedTargetScopes = setOf(
                        TargetTopologyScope.PRIVATE_LAN,
                        TargetTopologyScope.LINK_LOCAL,
                        TargetTopologyScope.LOOPBACK,
                        TargetTopologyScope.CARRIER_GRADE_NAT,
                        TargetTopologyScope.HOSTNAME_OR_UNRESOLVED,
                        TargetTopologyScope.UNKNOWN,
                    ),
                    capabilitiesFresh = true,
                ),
            ),
        )

        assertNotNull(selection)
        assertEquals("lan", selection.candidateId)
        assertEquals(TargetTopologyScope.PRIVATE_LAN, selection.targetSummary.scopes.single())
        assertTrue(selection.reason.contains("LAN agent"))
    }

    @Test
    fun `routing advisor prefers general delegated executor for public internet targets`() {
        val selection = DelegatedExecutorRoutingAdvisor.select(
            targets = listOf("8.8.8.8"),
            candidates = listOf(
                DelegatedExecutorRoutingCandidate(
                    id = "primary",
                    label = "Primary delegated executor",
                    configured = true,
                    kind = ExecutorNodeKind.REMOTE_NMAP,
                    capabilitiesFresh = true,
                ),
                DelegatedExecutorRoutingCandidate(
                    id = "lan",
                    label = "LAN agent",
                    configured = true,
                    kind = ExecutorNodeKind.LAN_AGENT,
                    allowedTargetScopes = setOf(
                        TargetTopologyScope.PRIVATE_LAN,
                        TargetTopologyScope.LINK_LOCAL,
                        TargetTopologyScope.LOOPBACK,
                    ),
                    capabilitiesFresh = true,
                ),
            ),
        )

        assertNotNull(selection)
        assertEquals("primary", selection.candidateId)
        assertTrue(selection.reason.contains("public-internet"))
    }

    @Test
    fun `routing advisor rejects lan agent when target scope is outside its policy`() {
        val selection = DelegatedExecutorRoutingAdvisor.select(
            targets = listOf("8.8.8.8"),
            candidates = listOf(
                DelegatedExecutorRoutingCandidate(
                    id = "lan",
                    label = "LAN agent",
                    configured = true,
                    kind = ExecutorNodeKind.LAN_AGENT,
                    allowedTargetScopes = setOf(
                        TargetTopologyScope.PRIVATE_LAN,
                        TargetTopologyScope.LINK_LOCAL,
                        TargetTopologyScope.LOOPBACK,
                    ),
                    capabilitiesFresh = false,
                ),
            ),
        )

        assertNull(selection)
    }
}
