package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StructuredOptionsTest {
    @Test
    fun `structured nmap options render deterministically`() {
        val result = StructuredNmapArgumentComposer.build(
            StructuredNmapOptions(
                skipHostDiscovery = true,
                enableServiceDetection = true,
                timingTemplate = NmapTimingTemplate.AGGRESSIVE,
                portList = "22,80,443",
                scriptSelection = "default,safe",
                extraArguments = "-F --reason",
            ),
        )

        assertTrue(result.isValid)
        assertEquals(
            "-Pn -sV -T4 -p 22,80,443 --script default,safe -F --reason",
            result.value,
        )
    }

    @Test
    fun `structured nmap options reject conflicting port controls`() {
        val result = StructuredNmapArgumentComposer.build(
            StructuredNmapOptions(
                portList = "80,443",
                topPorts = "100",
            ),
        )

        assertFalse(result.isValid)
        assertTrue(result.issues.any { it.field == "structured.portStrategy" })
    }

    @Test
    fun `structured nmap options reject managed flags in extra arguments`() {
        val result = StructuredNmapArgumentComposer.build(
            StructuredNmapOptions(extraArguments = "-Pn -F"),
        )

        assertFalse(result.isValid)
        assertTrue(result.issues.any { it.message.contains("structured Nmap options") })
    }

    @Test
    fun `raw nmap arguments can be inferred into structured state`() {
        val inferred = StructuredNmapArgumentComposer.inferFromRawArguments(
            "-Pn -sV -T4 -p 22,80 --script default,safe -F --reason",
        )

        assertTrue(inferred.skipHostDiscovery)
        assertTrue(inferred.enableServiceDetection)
        assertEquals(NmapTimingTemplate.AGGRESSIVE, inferred.timingTemplate)
        assertEquals("22,80", inferred.portList)
        assertEquals("default,safe", inferred.scriptSelection)
        assertEquals("-F --reason", inferred.extraArguments)
    }
}
