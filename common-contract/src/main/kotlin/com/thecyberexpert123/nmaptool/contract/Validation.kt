package com.thecyberexpert123.nmaptool.contract

private const val MAX_PROFILE_NAME_LENGTH = 80
private const val MAX_ARGUMENT_LENGTH = 256
private const val MAX_TARGET_LENGTH = 253
private const val MAX_TARGETS = 64
private const val MAX_ARGUMENTS = 128

private val targetPattern = Regex("^[A-Za-z0-9._:/%\\[\\]-]+$")
private val controlCharacterPattern = Regex("[\\u0000\\n\\r]")

object TargetParser {
    fun parse(rawTargets: String): List<String> =
        rawTargets
            .split(',', '\n')
            .asSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toList()
}

object TargetValidator {
    fun validate(targets: List<String>): List<ValidationIssue> {
        val issues = mutableListOf<ValidationIssue>()

        if (targets.isEmpty()) {
            issues += ValidationIssue(field = "targets", message = "At least one target is required.")
            return issues
        }

        if (targets.size > MAX_TARGETS) {
            issues += ValidationIssue(
                field = "targets",
                message = "A single request can include at most $MAX_TARGETS targets.",
            )
        }

        targets.forEachIndexed { index, target ->
            when {
                target.length > MAX_TARGET_LENGTH -> issues += ValidationIssue(
                    field = "targets[$index]",
                    message = "Target exceeds the supported length of $MAX_TARGET_LENGTH characters.",
                )

                !targetPattern.matches(target) -> issues += ValidationIssue(
                    field = "targets[$index]",
                    message = "Target contains unsupported characters: $target",
                )
            }
        }

        return issues
    }
}

object ArgumentTokenizer {
    fun tokenize(rawArguments: String): List<String> {
        if (rawArguments.isBlank()) {
            return emptyList()
        }

        val tokens = mutableListOf<String>()
        val current = StringBuilder()
        var quote: Char? = null
        var escaping = false

        rawArguments.forEach { character ->
            when {
                escaping -> {
                    current.append(character)
                    escaping = false
                }

                character == '\\' -> escaping = true
                quote != null && character == quote -> quote = null
                quote == null && (character == '"' || character == '\'') -> quote = character
                quote == null && character.isWhitespace() -> {
                    if (current.isNotEmpty()) {
                        tokens += current.toString()
                        current.setLength(0)
                    }
                }

                else -> current.append(character)
            }
        }

        require(!escaping) { "Dangling escape sequence in expert arguments." }
        require(quote == null) { "Unclosed quoted argument in expert arguments." }

        if (current.isNotEmpty()) {
            tokens += current.toString()
        }

        return tokens
    }
}

object CommandSafetyPolicy {
    private val exactDeniedFlagsByTool: Map<ToolType, Set<String>> = mapOf(
        ToolType.NMAP to setOf(
            "-iL",
            "--append-output",
            "--resume",
            "--datadir",
            "--servicedb",
            "--versiondb",
            "--excludefile",
            "--stylesheet",
            "--webxml",
            "--script-updatedb",
        ),
        ToolType.NCAT to setOf(
            "-e",
            "--exec",
            "-c",
            "--sh-exec",
            "--lua-exec",
        ),
        ToolType.NPING to emptySet(),
    )

    private val deniedPrefixesByTool: Map<ToolType, Set<String>> = mapOf(
        ToolType.NMAP to setOf(
            "-o",
            "--datadir=",
            "--servicedb=",
            "--versiondb=",
            "--excludefile=",
            "--stylesheet=",
            "--webxml=",
        ),
        ToolType.NCAT to emptySet(),
        ToolType.NPING to emptySet(),
    )

    fun validate(tool: ToolType, arguments: List<String>): List<ValidationIssue> {
        val issues = mutableListOf<ValidationIssue>()

        if (arguments.size > MAX_ARGUMENTS) {
            issues += ValidationIssue(
                field = "arguments",
                message = "A single request can include at most $MAX_ARGUMENTS arguments.",
            )
        }

        arguments.forEachIndexed { index, argument ->
            when {
                argument.isBlank() -> issues += ValidationIssue(
                    field = "arguments[$index]",
                    message = "Arguments must not be blank.",
                )

                argument.length > MAX_ARGUMENT_LENGTH -> issues += ValidationIssue(
                    field = "arguments[$index]",
                    message = "Argument exceeds $MAX_ARGUMENT_LENGTH characters.",
                )

                controlCharacterPattern.containsMatchIn(argument) -> issues += ValidationIssue(
                    field = "arguments[$index]",
                    message = "Arguments must not contain control characters.",
                )

                exactDeniedFlagsByTool[tool].orEmpty().contains(argument) -> issues += ValidationIssue(
                    field = "arguments[$index]",
                    message = "Argument is blocked for security reasons: $argument",
                )

                deniedPrefixesByTool[tool].orEmpty().any(argument::startsWith) -> issues += ValidationIssue(
                    field = "arguments[$index]",
                    message = "Argument is blocked for security reasons: $argument",
                )
            }
        }

        return issues
    }
}

object InvocationFactory {
    fun fromDraft(
        profileName: String,
        tool: ToolType,
        executionPreference: ExecutionPreference,
        rawTargets: String,
        rawArguments: String,
        notes: String,
        requestedBy: RunTrigger,
        requestedAtEpochMillis: Long = System.currentTimeMillis(),
    ): ValidationResult<ValidatedToolInvocation> {
        val issues = mutableListOf<ValidationIssue>()
        val normalizedName = profileName.trim()

        if (normalizedName.isEmpty()) {
            issues += ValidationIssue(field = "profileName", message = "Profile name is required.")
        } else if (normalizedName.length > MAX_PROFILE_NAME_LENGTH) {
            issues += ValidationIssue(
                field = "profileName",
                message = "Profile name must be at most $MAX_PROFILE_NAME_LENGTH characters.",
            )
        }

        val targets = TargetParser.parse(rawTargets)
        issues += TargetValidator.validate(targets)

        val arguments = try {
            ArgumentTokenizer.tokenize(rawArguments)
        } catch (error: IllegalArgumentException) {
            issues += ValidationIssue(field = "arguments", message = error.message ?: "Invalid arguments.")
            emptyList()
        }
        issues += CommandSafetyPolicy.validate(tool, arguments)

        if (issues.isNotEmpty()) {
            return ValidationResult.failure(issues)
        }

        return ValidationResult.success(
            ValidatedToolInvocation(
                request = ToolInvocationRequest(
                    profileName = normalizedName,
                    tool = tool,
                    executionPreference = executionPreference,
                    targets = targets,
                    arguments = arguments,
                    notes = notes.trim(),
                    requestedAtEpochMillis = requestedAtEpochMillis,
                    requestedBy = requestedBy,
                ),
            ),
        )
    }
}
