# Android Nmap Tool

Android Nmap Tool is a production-oriented, open-source foundation for a **capability-aware Android network-scanning platform**.

It is designed around one hard technical reality:

- **non-root Android devices cannot honestly provide full desktop Nmap parity locally**, because several Nmap capabilities depend on raw-packet privileges and related low-level access.
- therefore this project uses a **distributed execution model**:
  - **Android-local socket-based execution** for the subset of transport probing that stock Android legitimately permits,
  - **delegated execution** for broader and more privileged scan behavior on capable endpoints,
  - **transparent capability routing** so the app never pretends a capability exists when it does not.

## Project goals

- Android UI for scan building, saved profiles, history, automation, and settings
- Support for `nmap`, `ncat`, and `nping`
- Expert-argument mode for broad CLI compatibility
- Autonomous recurring execution using Android-compliant scheduling primitives
- Secure delegated-executor integration with encrypted token storage on Android
- Clear documentation, auditability, and scope discipline

## Current repository contents

This repository now contains:

- `app/` — Android app using Kotlin + Jetpack Compose + Room + WorkManager
- `common-contract/` — shared request/response models, validation logic, structured parsing, and report rendering used by both Android and backend
- `remote-executor/` — Ktor-based delegated backend that runs validated tool requests through `ProcessBuilder`
- `CHANGELOG.md` — incremental change tracking
- `AGENT-EXPERIENCE.md` — development decisions, lessons, and constraints

## Architecture overview

```text
Android app
 ├─ Scan builder UI
 ├─ Saved profiles
 ├─ Automation / WorkManager scheduling
 ├─ History and result inspection
 ├─ Executor configuration
 └─ Capability router
        │
        ├─ Android-local executor
        │    ├─ TCP connect scanning for bounded Nmap-compatible profiles
        │    ├─ curated service identification for selected Android-local `-sV` flows
        │    ├─ evidence-based OS-family / device-type inference for selected Android-local `-O` flows
        │    ├─ single-target TCP session probing for bounded Ncat-style use
        │    └─ bounded TCP-connect / UDP datagram timing probes for Android-local Nping mode
        │
        └─ Delegated executor client
             └─ structured JSON API to a legitimate capable endpoint

Shared contract module
 ├─ tool enums
 ├─ request/response models
 ├─ capability-profile models
 ├─ target parsing
 ├─ expert-argument tokenization
 ├─ command safety policy
 └─ deterministic command preview generation

Delegated executor
 ├─ capability endpoint
 ├─ execute endpoint
 ├─ bearer-token gate
 ├─ tool allowlist: nmap, ncat, nping
 └─ process execution with timeout
```

## Capability delegation principle

This project is now framed around one architectural rule:

> If Android cannot legitimately perform an operation itself, the app should not try to bypass Android's security boundary. It should delegate that operation to an executor that already has the required capability.

That means:

- Android-local execution remains useful for socket-compatible scans.
- Delegated execution is the honest path for raw-packet-sensitive or fuller-parity Nmap behavior.
- The app is the planner, router, UI, and analysis surface; it is not required to be the place where every packet is created.

## Transport is not privilege

The project keeps transport and execution capability separate:

- **HTTPS / ordinary networking** can carry authenticated scan requests.
- **VPN tunnels** can provide secure or private connectivity to an executor.
- **Routers / LAN appliances** only become executors when they actually run authorized software that accepts requests and performs scans.

In other words:

- encryption does not create privilege
- tunneling does not create packet-crafting capability
- forwarding does not equal packet generation

## Why the distributed model is required

Some Nmap scan classes rely on privileged raw-packet access. On Unix-like systems, SYN scan and several low-level modes require elevated privileges. Modern Android also restricts background work and long-running execution, so recurring scans must use platform-compliant scheduling such as WorkManager and foreground execution patterns where needed.

This project chooses correctness over false claims:

- **Android-local mode** is limited to what stock Android socket APIs can actually do
- **delegated executor mode** is the primary compatibility path for broader/full Nmap behavior on non-root devices
- **auto mode** prefers Android-local execution only when the current request fits the bounded local transport subset; otherwise it routes to a delegated executor when possible instead of failing silently

## Android app features in this milestone

### Implemented foundation
- Compose-based multi-tab UI:
  - Dashboard
  - Builder
  - History
  - Automation
  - Settings
- Real **Android-local transport execution** for stock, non-root devices:
  - bounded TCP connect scanning for local Nmap-compatible profiles
  - bounded curated service identification for selected local `-sV` Nmap-compatible profiles
  - bounded evidence-based OS-family and device-type inference for selected local `-O` Nmap-compatible profiles
  - single-target TCP session probing for local Ncat-compatible profiles
  - bounded TCP-connect or UDP datagram timing probes for local Nping-compatible profiles
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
- Delegated executor settings with **Android Keystore-encrypted bearer token storage**
- Capability refresh from delegated executors
- Automatic capability re-check after saving delegated executor settings
- Capability staleness tracking when settings are edited after a refresh
- Shared executor capability profiles for Android-local and delegated execution nodes, including feature matrices and execution limits
- Delegated capability detail reporting for executor label plus detected `nmap` / `ncat` / `nping` version banners when available
- Builder-side execution guidance that explains likely route, likely executor, blockers, warnings, and privileged-access caveats before a run is launched
- Shared execution-route selection so builder guidance and actual AUTO dispatch use the same delegated-vs-local preference rules
- Execution result persistence and history cards
- Run-to-run **delta summaries** for the same profile to highlight status, route, exit-code, command, or output changes
- Dashboard insight cards for:
  - observed hosts from parsed findings
  - open endpoints seen in recent runs
  - recent port-change alerts
  - scheduled-profile and recent-failure visibility
- Shared **result parsing** for richer summaries:
  - Nmap host/up/open-port extraction from standard output
  - Nping packet and RTT summary extraction
  - Ncat connection/output highlight extraction
- Parsed **host/port change detection** for repeated Nmap runs:
  - newly open endpoints since the previous run
  - previously open endpoints no longer present
- Profile and automation views now surface saved schedule cadence and the most recent run outcome for faster operator triage.
- Run history now surfaces parse provenance, execution duration, observed-host counts, explicit capture-truncation warnings, and remote request/executor identifiers when available.
- History now includes built-in **report export generation** with Markdown and CSV outputs derived from saved run history.
- History can now export reports to a user-selected document destination and prepare shareable report files through Android's document/share flows.
- Builder guidance now warns when the current profile is likely to depend on remote execution, stale capability data, unavailable tool binaries, or privilege-sensitive scan modes.

### Explicit current limitation
- The Android app now includes a **real Android-local execution baseline**, but it is intentionally limited to what stock non-root Android socket APIs can honestly do.
- Android-local phase-C execution does **not** claim parity with raw-packet Nmap features such as SYN scan, OS detection parity, NSE/default scripts, or traceroute.
- Android-local Nmap mode supports bounded TCP connect scanning, a curated `-sV` subset for selected protocols such as HTTP, TLS/HTTPS, SSH, and banner-oriented services, plus evidence-based local `-O` inference for selected OS-family and device-type hints.
- Android-local Nmap mode still requires an explicit TCP port strategy such as `-p`, `--top-ports`, or `-F`.
- Android-local `-sV` is intentionally limited and bounded; it is not full Nmap version detection parity, and AUTO mode will still prefer a delegated executor when broader semantics are available.
- Android-local `-O` is also intentionally limited: it produces evidence-based local inference rather than Nmap TCP/IP stack fingerprinting parity, and it benefits from `-sV` when more banner evidence is needed.
- Android-local Ncat/Nping support is likewise bounded and intentionally conservative.
- If you need broader/full Nmap behavior, configure a delegated executor such as the current remote Linux Nmap backend.

## Security model

### Android app
- target input is parsed and validated before persistence or execution
- expert arguments are tokenized and validated, not shell-concatenated
- Android-local execution stays inside permitted app-level socket APIs rather than attempting SELinux or privilege-boundary bypasses
- Android-local runs are bounded by local target/port/probe limits to avoid misleading parity claims and excessive on-device socket fan-out
- remote bearer token is encrypted with Android Keystore before storage
- automation uses WorkManager rather than unrestricted background processes

### Delegated executor
- uses structured JSON requests, not raw shell command strings
- invokes tools with `ProcessBuilder` argv lists
- rejects security-sensitive flags that would enable:
  - output file writes
  - executor-side file input indirection
  - ncat command execution modes
- for `nmap` requests, the executor can capture **normal output plus structured XML output** using executor-managed temporary files for programmatic parsing
- returns explicit truncation metadata for stdout, stderr, and structured XML captures so the Android client can warn about incomplete results
- publishes a feature-based executor capability profile in addition to raw tool-availability fields
- can enforce an executor-side concurrency ceiling to reduce host overload
- can append lightweight JSONL audit events with request IDs, execution outcome, and truncation metadata
- optional bearer token protection via `NMAP_EXECUTOR_TOKEN`
- optional executor identity metadata via `EXECUTOR_NODE_KIND` and `EXECUTOR_TRANSPORT_KIND`
- optional target-scope restriction via `ALLOWED_TARGET_REGEXES` and `ALLOWED_TARGET_SCOPES`
- bounded output capture via `MAX_OUTPUT_BYTES`
- enforces execution timeout

## Supported delegated executor environment variables

| Variable | Purpose | Default |
|---|---|---|
| `PORT` | HTTP server port | `8080` |
| `NMAP_EXECUTOR_TOKEN` | Optional bearer token required by API | unset |
| `EXECUTOR_LABEL` | Optional human-readable label returned in capability reports and run audit metadata | hostname or `remote-executor` |
| `EXECUTOR_NODE_KIND` | Declares the executor role reported to Android (`REMOTE_NMAP`, `LAN_AGENT`, `UNKNOWN`) | `REMOTE_NMAP` |
| `EXECUTOR_TRANSPORT_KIND` | Declares how the executor is reached (`HTTPS`, `PRIVATE_OVERLAY`, `VPN_TUNNEL`, `UNKNOWN`) | `HTTPS` |
| `NMAP_BINARY` | Path or command name for `nmap` | `nmap` |
| `NCAT_BINARY` | Path or command name for `ncat` | `ncat` |
| `NPING_BINARY` | Path or command name for `nping` | `nping` |
| `EXECUTION_TIMEOUT_SECONDS` | Maximum runtime per request | `900` |
| `MAX_OUTPUT_BYTES` | Per-stream capture limit for stdout/stderr and executor-managed Nmap output files | `262144` |
| `MAX_CONCURRENT_EXECUTIONS` | Maximum simultaneous in-flight executions allowed by the delegated executor | `2` |
| `AUDIT_LOG_PATH` | Optional JSONL audit log destination for request/execution events | unset |
| `ALLOWED_TARGET_REGEXES` | Optional semicolon-separated regex allowlist for targets | unset |
| `ALLOWED_TARGET_SCOPES` | Optional semicolon-separated target topology scopes allowed by this executor | all scopes |

## Build requirements

### Android app
- JDK 17
- Android SDK / Build Tools compatible with AGP 9.2
- Android Studio version compatible with AGP 9.2+

### Delegated executor
- JDK 17
- `nmap`, `ncat`, `nping` installed on the host according to your deployment plan

## Build and run

### Android app
```bash
./gradlew :app:assembleDebug
```

### Delegated executor
```bash
./gradlew :remote-executor:run
```

Example secured run:

```bash
export NMAP_EXECUTOR_TOKEN="replace-me"
export EXECUTOR_LABEL="lab-east-1"
export MAX_CONCURRENT_EXECUTIONS="2"
export AUDIT_LOG_PATH="./logs/executor-audit.jsonl"
export NMAP_BINARY="nmap"
export NCAT_BINARY="ncat"
export NPING_BINARY="nping"
# Optional when this node is a private-network LAN agent:
# export EXECUTOR_NODE_KIND="LAN_AGENT"
# export EXECUTOR_TRANSPORT_KIND="PRIVATE_OVERLAY"
# export ALLOWED_TARGET_SCOPES="PRIVATE_LAN;LINK_LOCAL;LOOPBACK;CARRIER_GRADE_NAT;HOSTNAME_OR_UNRESOLVED;UNKNOWN"
./gradlew :remote-executor:run
```

## Example workflow

1. Install the Android app.
2. If you want broader/full Nmap coverage, start one or both delegated executors on hosts you control:
   - a primary delegated executor for general remote scans,
   - an optional LAN agent near the private network you want to scan.
3. Open **Settings** and configure the primary delegated executor and, when needed, the LAN-agent base URL plus optional bearer tokens.
4. Refresh capabilities to confirm each delegated backend sees `nmap`, `ncat`, and `nping`, advertises the expected executor role, and reports the intended target-topology policy. Use **Refresh local snapshot** to review stock-device limits.
5. Build a profile in **Builder** using:
   - targets,
   - tool selection,
   - structured Nmap controls where applicable,
   - extra expert arguments,
   - execution mode,
   - optional recurring schedule.
6. Review the live effective-argument preview, command preview, and execution-guidance card to see whether the profile is Android-local compatible or should route to a delegated executor.
7. Save the profile and run it manually or let automation trigger it.
8. Inspect recent host/endpoint activity and port-change alerts in **Dashboard**.
9. Inspect status, logs, parsed findings, run-to-run deltas, and request/executor audit metadata in **History**.
10. Generate a Markdown or CSV report preview from saved history, then copy it, export it to a document destination, or share it through Android's share sheet.

## Result summaries

The app now derives lightweight summaries from captured tool output to make repeated scans easier to inspect.

### Current parsing behavior
- **Nmap**:
  - prefers structured XML output when the delegated executor provides it,
  - falls back to heuristic stdout parsing when XML is unavailable,
  - also parses the Android-local TCP connect report format, including curated local service-detail lines and local fingerprint-inference lines, into the same saved summary model,
  - extracts host report lines, host-up indicators, open/open-filtered port entries, not-shown summaries, service/detail text, local device/OS inference highlights, and completion duration.
- **Nping**: extracts packet send/receive/loss information and RTT min/avg/max lines when present.
- **Ncat**: surfaces connection target and first output line when present.
- Each parsed run now records whether the summary came from structured Nmap XML, heuristic text parsing, or no parseable captured content.
- Capture truncation is reported explicitly so operators can distinguish “no findings” from “possibly incomplete findings due to capture limits.”

### Change detection behavior
- For repeated **Nmap** runs of the same saved profile, the app compares parsed open endpoints between the latest run and the previous run.
- It highlights:
  - newly open endpoints
  - previously open endpoints no longer present
- Non-Nmap tools currently keep generic delta reporting only.

### Important limitation
- XML-based summaries are more reliable than heuristic stdout parsing, but they still depend on the delegated executor actually returning intact XML within capture limits.
- The app now preserves truncation metadata and warns when saved outputs were incomplete, but truncation still reduces the fidelity of any parsed summary.
- Android-local output is intentionally compatibility-oriented and conservative. Even when curated local service identification or fingerprint inference is present, it remains a bounded socket-level approximation rather than a claim of raw-packet, full version-detection, or full TCP/IP stack fingerprinting parity.
- Android-local UDP no-response results remain inherently inconclusive on stock Android because the app does not have full raw ICMP visibility.
- Builder execution guidance is advisory. It improves honesty before execution, but it cannot prove that a given remote host, network path, or privilege-sensitive scan mode will succeed in every environment.
- Exported Markdown/CSV reports and SAF/share artifacts reflect only the runs saved in local history; they are reporting artifacts, not a substitute for build/runtime verification or full raw upstream output retention.
- Non-Nmap tool summaries and fallback text parsing remain **heuristic**, not a claim of complete semantic understanding of every possible upstream output format or localization variant.

## Command safety policy

This project allows expert-style arguments, but it still blocks a narrow set of dangerous options on the delegated executor. It also uses pre-run execution guidance in the Android builder to surface route assumptions and privilege-sensitive scan caveats before the operator launches a profile.

### Blocked examples
- Nmap output file flags such as `-o*`
- Nmap file/path flags such as `-iL`, `--datadir`, `--excludefile`, `--resume`
- Ncat command execution flags such as `-e`, `-c`, `--exec`, `--sh-exec`, `--lua-exec`

That policy exists to preserve operator safety and host integrity in a mobile-controlled executor model.

## Roadmap

### Next milestones
1. deeper delegated-executor routing verification and policy UX refinement across Android-local, LAN-agent, and remote-Nmap routes
2. richer Nmap result modeling using structured output formats where feasible
3. optional authenticated multi-user delegated-executor governance beyond the current single-token deployment model
4. deeper delegated-executor observability such as richer backend metrics/retention controls around audit logs
5. broader delegated execution management such as health/history for multiple registered executor nodes

## Verification status

### Verified in this repository session
- repository baseline was inspected before modification
- Android + backend source structure was created
- shared validation logic and tests were added
- Gradle wrapper files were added to the repository

### Not verified in this repository session
- Android compilation
- emulator/device runtime behavior
- delegated executor runtime behavior

The current sandbox does not have Java installed, so build execution could not be performed here. No test or build success is claimed beyond the source changes present in the repository.
