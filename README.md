# Android Nmap Tool

Android Nmap Tool is a production-oriented, open-source foundation for a **hybrid Nmap client on Android**.

It is designed around one hard technical reality:

- **non-root Android devices cannot honestly provide full desktop Nmap parity locally**, because several Nmap capabilities depend on raw-packet privileges and related low-level access.
- therefore this project uses a **hybrid execution model**:
  - **remote execution** for broad and honest feature coverage on modern non-root Android devices,
  - **local capability detection** and future local execution integration where device/runtime support exists,
  - **transparent execution routing** so the app never pretends a capability exists when it does not.

## Project goals

- Android UI for scan building, saved profiles, history, automation, and settings
- Support for `nmap`, `ncat`, and `nping`
- Expert-argument mode for broad CLI compatibility
- Autonomous recurring execution using Android-compliant scheduling primitives
- Secure remote executor integration with encrypted token storage on Android
- Clear documentation, auditability, and scope discipline

## Current repository contents

This repository now contains:

- `app/` — Android app using Kotlin + Jetpack Compose + Room + WorkManager
- `common-contract/` — shared request/response models and validation logic used by both Android and backend
- `remote-executor/` — Ktor-based backend that runs validated tool requests through `ProcessBuilder`
- `CHANGELOG.md` — incremental change tracking
- `AGENT-EXPERIENCE.md` — development decisions, lessons, and constraints

## Architecture overview

```text
Android app
 ├─ Scan builder UI
 ├─ Saved profiles
 ├─ Automation / WorkManager scheduling
 ├─ History and result inspection
 ├─ Remote endpoint configuration
 └─ Execution routing
        │
        ├─ Local executor contract
        │    └─ currently reports local execution unavailable in this baseline
        │
        └─ Remote executor client
             └─ shared validation + structured JSON API

Shared contract module
 ├─ tool enums
 ├─ request/response models
 ├─ target parsing
 ├─ expert-argument tokenization
 ├─ command safety policy
 └─ deterministic command preview generation

Remote executor
 ├─ capability endpoint
 ├─ execute endpoint
 ├─ bearer-token gate
 ├─ tool allowlist: nmap, ncat, nping
 └─ process execution with timeout
```

## Why the hybrid model is required

Some Nmap scan classes rely on privileged raw-packet access. On Unix-like systems, SYN scan and several low-level modes require elevated privileges. Modern Android also restricts background work and long-running execution, so recurring scans must use platform-compliant scheduling such as WorkManager and foreground execution patterns where needed.

This project chooses correctness over false claims:

- **remote mode** is the primary compatibility path for non-root devices
- **local mode** remains explicitly capability-gated
- **auto mode** chooses the best supported route instead of failing silently

## Android app features in this milestone

### Implemented foundation
- Compose-based multi-tab UI:
  - Dashboard
  - Builder
  - History
  - Automation
  - Settings
- Profile creation and editing
- Support for `nmap`, `ncat`, `nping`
- Presets plus expert CLI argument entry
- **Structured Nmap builder controls** for common flags:
  - `-Pn`
  - `-sV`
  - `-sC`
  - `-O`
  - `--traceroute`
  - timing template selection (`-T0` to `-T5`)
  - explicit port list / top-ports mode
  - script selection
- Live effective-argument preview and full command preview
- Shared validation for targets and arguments
- Room persistence for profiles, schedules, and run history
- WorkManager-based recurring scan scheduling
- Remote executor settings with **Android Keystore-encrypted bearer token storage**
- Capability refresh from the backend
- Execution result persistence and history cards
- Run-to-run **delta summaries** for the same profile to highlight status, route, exit-code, command, or output changes
- Dashboard insight cards for:
  - observed hosts from parsed findings
  - open endpoints seen in recent runs
  - recent port-change alerts
- Shared **result parsing** for richer summaries:
  - Nmap host/up/open-port extraction from standard output
  - Nping packet and RTT summary extraction
  - Ncat connection/output highlight extraction
- Parsed **host/port change detection** for repeated Nmap runs:
  - newly open endpoints since the previous run
  - previously open endpoints no longer present

### Explicit current limitation
- The Android app's **local executor is intentionally disabled in this baseline**.
- This is deliberate: the repository does not yet bundle or ship native Nmap binaries, and the project will not fake on-device parity.
- If you want meaningful execution today, configure the remote executor.

## Security model

### Android app
- target input is parsed and validated before persistence or execution
- expert arguments are tokenized and validated, not shell-concatenated
- remote bearer token is encrypted with Android Keystore before storage
- automation uses WorkManager rather than unrestricted background processes

### Remote executor
- uses structured JSON requests, not raw shell command strings
- invokes tools with `ProcessBuilder` argv lists
- rejects security-sensitive flags that would enable:
  - output file writes
  - executor-side file input indirection
  - ncat command execution modes
- for `nmap` requests, the executor can capture **normal output plus structured XML output** using executor-managed temporary files for programmatic parsing
- optional bearer token protection via `NMAP_EXECUTOR_TOKEN`
- optional target-scope restriction via `ALLOWED_TARGET_REGEXES`
- bounded output capture via `MAX_OUTPUT_BYTES`
- enforces execution timeout

## Supported remote executor environment variables

| Variable | Purpose | Default |
|---|---|---|
| `PORT` | HTTP server port | `8080` |
| `NMAP_EXECUTOR_TOKEN` | Optional bearer token required by API | unset |
| `NMAP_BINARY` | Path or command name for `nmap` | `nmap` |
| `NCAT_BINARY` | Path or command name for `ncat` | `ncat` |
| `NPING_BINARY` | Path or command name for `nping` | `nping` |
| `EXECUTION_TIMEOUT_SECONDS` | Maximum runtime per request | `900` |
| `MAX_OUTPUT_BYTES` | Per-stream capture limit for stdout/stderr | `262144` |
| `ALLOWED_TARGET_REGEXES` | Optional semicolon-separated regex allowlist for targets | unset |

## Build requirements

### Android app
- JDK 17
- Android SDK / Build Tools compatible with AGP 9.2
- Android Studio version compatible with AGP 9.2+

### Remote executor
- JDK 17
- `nmap`, `ncat`, `nping` installed on the host according to your deployment plan

## Build and run

### Android app
```bash
./gradlew :app:assembleDebug
```

### Remote executor
```bash
./gradlew :remote-executor:run
```

Example secured run:

```bash
export NMAP_EXECUTOR_TOKEN="replace-me"
export NMAP_BINARY="nmap"
export NCAT_BINARY="ncat"
export NPING_BINARY="nping"
./gradlew :remote-executor:run
```

## Example workflow

1. Start the remote executor on a host you control.
2. Install the Android app.
3. Open **Settings** and configure the remote base URL and optional bearer token.
4. Refresh capabilities to confirm the backend sees `nmap`, `ncat`, and `nping`.
5. Build a profile in **Builder** using:
   - targets,
   - tool selection,
   - structured Nmap controls where applicable,
   - extra expert arguments,
   - execution mode,
   - optional recurring schedule.
6. Review the live effective-argument preview and command preview.
7. Save the profile and run it manually or let automation trigger it.
8. Inspect recent host/endpoint activity and port-change alerts in **Dashboard**.
9. Inspect status, logs, parsed findings, and run-to-run deltas in **History**.

## Result summaries

The app now derives lightweight summaries from captured tool output to make repeated scans easier to inspect.

### Current parsing behavior
- **Nmap**:
  - prefers structured XML output when the remote executor provides it,
  - falls back to heuristic stdout parsing when XML is unavailable,
  - extracts host report lines, host-up indicators, open/open-filtered port entries, not-shown summaries, and completion duration.
- **Nping**: extracts packet send/receive/loss information and RTT min/avg/max lines when present.
- **Ncat**: surfaces connection target and first output line when present.

### Change detection behavior
- For repeated **Nmap** runs of the same saved profile, the app compares parsed open endpoints between the latest run and the previous run.
- It highlights:
  - newly open endpoints
  - previously open endpoints no longer present
- Non-Nmap tools currently keep generic delta reporting only.

### Important limitation
- XML-based summaries are more reliable than heuristic stdout parsing, but they still depend on the remote executor actually returning intact XML within capture limits.
- Non-Nmap tool summaries and fallback text parsing remain **heuristic**, not a claim of complete semantic understanding of every possible upstream output format or localization variant.

## Command safety policy

This project allows expert-style arguments, but it still blocks a narrow set of dangerous options on the remote executor.

### Blocked examples
- Nmap output file flags such as `-o*`
- Nmap file/path flags such as `-iL`, `--datadir`, `--excludefile`, `--resume`
- Ncat command execution flags such as `-e`, `-c`, `--exec`, `--sh-exec`, `--lua-exec`

That policy exists to preserve operator safety and host integrity in a mobile-controlled executor model.

## Roadmap

### Next milestones
1. Local native execution integration strategy
   - bundled binaries, user-provided binaries, or companion runtime
2. richer Nmap result modeling using structured output formats where feasible
3. export/reporting formats
4. optional authenticated multi-user remote executor governance
5. local-vs-remote capability detection and policy UX refinement

## Verification status

### Verified in this repository session
- repository baseline was inspected before modification
- Android + backend source structure was created
- shared validation logic and tests were added
- Gradle wrapper files were added to the repository

### Not verified in this repository session
- Android compilation
- emulator/device runtime behavior
- remote executor runtime behavior

The current sandbox does not have Java installed, so build execution could not be performed here. No test or build success is claimed beyond the source changes present in the repository.
