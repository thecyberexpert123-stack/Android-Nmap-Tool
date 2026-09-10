package com.thecyberexpert123.nmaptool.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ValidationTest {
    @Test
    fun `tokenizer preserves quoted arguments`() {
        val tokens = ArgumentTokenizer.tokenize("-Pn --script \"default and safe\" --reason")

        assertEquals(listOf("-Pn", "--script", "default and safe", "--reason"), tokens)
    }

    @Test
    fun `target parser supports multiline and comma separated input`() {
        val targets = TargetParser.parse("scanme.nmap.org, 192.168.0.1\nfe80::1")

        assertEquals(listOf("scanme.nmap.org", "192.168.0.1", "fe80::1"), targets)
    }

    @Test
    fun `nmap output arguments are blocked`() {
        val result = InvocationFactory.fromDraft(
            profileName = "Unsafe output",
            tool = ToolType.NMAP,
            executionPreference = ExecutionPreference.REMOTE_ONLY,
            rawTargets = "scanme.nmap.org",
            rawArguments = "-Pn -oA findings",
            notes = "",
            requestedBy = RunTrigger.MANUAL,
        )

        assertFalse(result.isValid)
        assertTrue(result.issues.any { it.message.contains("blocked") })
    }

    @Test
    fun `valid expert profile builds a deterministic command preview`() {
        val result = InvocationFactory.fromDraft(
            profileName = "Service probe",
            tool = ToolType.NMAP,
            executionPreference = ExecutionPreference.AUTO,
            rawTargets = "scanme.nmap.org",
            rawArguments = "-Pn -sV",
            notes = "",
            requestedBy = RunTrigger.MANUAL,
        )

        assertTrue(result.isValid)
        assertEquals("nmap -Pn -sV scanme.nmap.org", result.value?.commandPreview)
    }
}
