package com.thecyberexpert123.nmaptool.contract

private val managedStructuredNmapFlags = setOf(
    "-Pn",
    "-sV",
    "-sC",
    "-O",
    "--traceroute",
)

private val timingTemplatePattern = Regex("^-T[0-5]$")

@kotlinx.serialization.Serializable
enum class NmapTimingTemplate(val cliToken: String?) {
    DEFAULT(null),
    PARANOID("-T0"),
    SNEAKY("-T1"),
    POLITE("-T2"),
    NORMAL("-T3"),
    AGGRESSIVE("-T4"),
    INSANE("-T5"),
}

@kotlinx.serialization.Serializable
data class StructuredNmapOptions(
    val skipHostDiscovery: Boolean = false,
    val enableServiceDetection: Boolean = false,
    val enableDefaultScripts: Boolean = false,
    val enableOsDetection: Boolean = false,
    val enableTraceroute: Boolean = false,
    val timingTemplate: NmapTimingTemplate = NmapTimingTemplate.DEFAULT,
    val portList: String = "",
    val topPorts: String = "",
    val scriptSelection: String = "",
    val extraArguments: String = "",
)

object StructuredNmapArgumentComposer {
    fun build(options: StructuredNmapOptions): ValidationResult<String> {
        val issues = mutableListOf<ValidationIssue>()
        val portList = options.portList.trim()
        val topPorts = options.topPorts.trim()
        val scriptSelection = options.scriptSelection.trim()

        if (portList.isNotEmpty() && topPorts.isNotEmpty()) {
            issues += ValidationIssue(
                field = "structured.portStrategy",
                message = "Choose either an explicit port list or a top-ports value, not both.",
            )
        }

        if (topPorts.isNotEmpty()) {
            val value = topPorts.toIntOrNull()
            if (value == null || value !in 1..65535) {
                issues += ValidationIssue(
                    field = "structured.topPorts",
                    message = "Top ports must be a whole number between 1 and 65535.",
                )
            }
        }

        val extraTokens = try {
            ArgumentTokenizer.tokenize(options.extraArguments)
        } catch (error: IllegalArgumentException) {
            issues += ValidationIssue(
                field = "structured.extraArguments",
                message = error.message ?: "Extra arguments are invalid.",
            )
            emptyList()
        }

        issues += findConflictingExtraArguments(extraTokens)
        issues += CommandSafetyPolicy.validate(ToolType.NMAP, extraTokens).map {
            it.copy(field = "structured.extraArguments")
        }

        if (issues.isNotEmpty()) {
            return ValidationResult.failure(issues)
        }

        val arguments = buildList {
            if (options.skipHostDiscovery) add("-Pn")
            if (options.enableServiceDetection) add("-sV")
            if (options.enableDefaultScripts) add("-sC")
            if (options.enableOsDetection) add("-O")
            if (options.enableTraceroute) add("--traceroute")
            options.timingTemplate.cliToken?.let(::add)
            if (portList.isNotEmpty()) {
                add("-p")
                add(portList)
            } else if (topPorts.isNotEmpty()) {
                add("--top-ports")
                add(topPorts)
            }
            if (scriptSelection.isNotEmpty()) {
                add("--script")
                add(scriptSelection)
            }
            addAll(extraTokens)
        }

        return ValidationResult.success(CommandPreview.renderArguments(arguments))
    }

    fun inferFromRawArguments(rawArguments: String): StructuredNmapOptions {
        val tokens = runCatching { ArgumentTokenizer.tokenize(rawArguments) }.getOrDefault(emptyList())
        var skipHostDiscovery = false
        var enableServiceDetection = false
        var enableDefaultScripts = false
        var enableOsDetection = false
        var enableTraceroute = false
        var timingTemplate = NmapTimingTemplate.DEFAULT
        var portList = ""
        var topPorts = ""
        var scriptSelection = ""
        val extraTokens = mutableListOf<String>()

        var index = 0
        while (index < tokens.size) {
            val token = tokens[index]
            when {
                token == "-Pn" -> skipHostDiscovery = true
                token == "-sV" -> enableServiceDetection = true
                token == "-sC" -> enableDefaultScripts = true
                token == "-O" -> enableOsDetection = true
                token == "--traceroute" -> enableTraceroute = true
                timingTemplatePattern.matches(token) -> {
                    timingTemplate = NmapTimingTemplate.entries.firstOrNull { it.cliToken == token }
                        ?: NmapTimingTemplate.DEFAULT
                }

                token == "-p" -> {
                    val value = tokens.getOrNull(index + 1)
                    if (value == null) {
                        extraTokens += token
                    } else {
                        portList = value
                        index += 1
                    }
                }

                token.startsWith("-p") && token.length > 2 -> portList = token.drop(2)
                token == "--top-ports" -> {
                    val value = tokens.getOrNull(index + 1)
                    if (value == null) {
                        extraTokens += token
                    } else {
                        topPorts = value
                        index += 1
                    }
                }

                token.startsWith("--top-ports=") -> topPorts = token.substringAfter('=')
                token == "--script" -> {
                    val value = tokens.getOrNull(index + 1)
                    if (value == null) {
                        extraTokens += token
                    } else {
                        scriptSelection = value
                        index += 1
                    }
                }

                token.startsWith("--script=") -> scriptSelection = token.substringAfter('=')
                else -> extraTokens += token
            }
            index += 1
        }

        return StructuredNmapOptions(
            skipHostDiscovery = skipHostDiscovery,
            enableServiceDetection = enableServiceDetection,
            enableDefaultScripts = enableDefaultScripts,
            enableOsDetection = enableOsDetection,
            enableTraceroute = enableTraceroute,
            timingTemplate = timingTemplate,
            portList = portList,
            topPorts = topPorts,
            scriptSelection = scriptSelection,
            extraArguments = CommandPreview.renderArguments(extraTokens),
        )
    }

    private fun findConflictingExtraArguments(arguments: List<String>): List<ValidationIssue> {
        val issues = mutableListOf<ValidationIssue>()
        arguments.forEachIndexed { index, argument ->
            when {
                managedStructuredNmapFlags.contains(argument) -> issues += ValidationIssue(
                    field = "structured.extraArguments[$index]",
                    message = "Move $argument into the structured Nmap options instead of extra arguments.",
                )

                timingTemplatePattern.matches(argument) -> issues += ValidationIssue(
                    field = "structured.extraArguments[$index]",
                    message = "Timing template should be selected through the structured control instead of extra arguments.",
                )

                argument == "-p" || argument.startsWith("-p") -> issues += ValidationIssue(
                    field = "structured.extraArguments[$index]",
                    message = "Port selection should be configured through the structured controls instead of extra arguments.",
                )

                argument == "--top-ports" || argument.startsWith("--top-ports=") -> issues += ValidationIssue(
                    field = "structured.extraArguments[$index]",
                    message = "Top ports should be configured through the structured controls instead of extra arguments.",
                )

                argument == "--script" || argument.startsWith("--script=") -> issues += ValidationIssue(
                    field = "structured.extraArguments[$index]",
                    message = "Script selection should be configured through the structured controls instead of extra arguments.",
                )
            }
        }
        return issues
    }
}
