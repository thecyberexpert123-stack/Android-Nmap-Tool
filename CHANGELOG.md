# CHANGELOG

All notable changes to this project will be documented in this file.

The format is intentionally simple and incremental so each agent session can append verifiable work without overstating implementation status.

## 2026-09-10

### Added
- Created `CHANGELOG.md` to track project changes incrementally and transparently.
- Created `AGENT-EXPERIENCE.md` to document development experience, challenges, and decisions.
- Bootstrapped a Gradle-based multi-module repository structure:
  - `app/` Android client
  - `common-contract/` shared validation and API contracts
  - `remote-executor/` Ktor backend
- Added Gradle wrapper files and version catalog.
- Added Android app manifest, theme/resources, application bootstrap, Room database, repository layer, WorkManager automation scheduler, foreground worker, Compose UI, and ViewModel.
- Added shared command/target validation, expert-argument tokenization, deterministic command preview generation, and JVM unit tests in `common-contract`.
- Added Ktor-based remote executor with capability and execution endpoints, bearer-token gate, structured request handling, process timeout support, and binary discovery.
- Expanded `README.md` into a production-oriented architecture, setup, security, workflow, and limitation document.

### Researched
- Inspected the repository baseline. Verified that the repository currently contains only `.git/` metadata and a minimal `README.md` with no Android source tree, build scripts, tests, or app modules.
- Verified upstream/official Nmap capability constraints relevant to Android implementation planning:
  - SYN scan (`-sS`) requires raw-packet privileges/root on Unix-like systems.
  - When privileged raw-packet access is unavailable, Nmap falls back to connect scans for supported cases.
  - Unprivileged users can only execute limited scan classes such as connect scans and FTP bounce scans.
- Verified Android platform constraints relevant to autonomous/background execution:
  - WorkManager is the recommended API for persistent, restart-resilient background work.
  - Long-running work on Android requires foreground execution patterns and user-visible notification handling.
  - Latest Compose setup uses the Compose Compiler Gradle plugin with Kotlin 2.x and BOM-managed dependencies.
  - Compose 1.12 requires compileSdk 37 and AGP 9.2.0+.
  - Current stable AndroidX versions relevant to the baseline include Activity Compose 1.13.0, Core/Core-KTX 1.19.0, Lifecycle 2.11.0, and WorkManager 2.11.2.
- Verified that Nmap redistribution/licensing requires an explicit product decision before shipping bundled binaries inside an Android app.

### Implemented
- Selected and implemented a **hybrid, non-root-first, open-source** baseline consistent with the user's confirmed direction.
- Chose a truthful execution posture:
  - remote execution is the primary path,
  - local execution is represented explicitly but currently unavailable in this baseline,
  - automation, history, and UI are still fully functional around that decision.
- Implemented secure Android-side remote settings handling with Android Keystore-backed token encryption.
- Implemented schedule persistence and recurring execution orchestration with WorkManager.
- Implemented structured support for `nmap`, `ncat`, and `nping` requests.
- Implemented a command safety policy that blocks remote-host-dangerous flags such as output-file redirection and Ncat process-exec modes.

### Verified Environment Facts
- Confirmed the current sandbox does not have `java` installed, so Gradle builds/tests cannot be executed here.
- Confirmed the repository now contains source code and build files but remains uncompiled in this environment.

### Not Yet Implemented
- No bundled native Android Nmap binaries are included yet.
- No rooted-device local execution path is included yet.
- No remote streaming/log tail API is implemented yet; current remote execution is request/response.
- No build or runtime verification has been performed because the environment lacks Java/Android SDK tooling.
