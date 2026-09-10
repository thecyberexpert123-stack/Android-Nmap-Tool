# AGENT-EXPERIENCE

This document records development observations, constraints, trade-offs, and learning moments encountered while building the project.

## 2026-09-10 — Initial inspection and implementation planning

### Repository reality check
- The repository is effectively empty from an Android product perspective. It currently contains only a minimal `README.md` and git metadata.
- Because there is no existing Gradle project, app module, CI setup, or test harness, the first production milestone must include project bootstrapping, architecture definition, and quality gates.

### Verified technical constraints
- Building an Android app that behaves like “actual Nmap” is not just a UI exercise. True Nmap parity depends on native executables and privilege-sensitive features.
- Some important Nmap capabilities require raw socket access or equivalent privileges. On Android, this means full parity is realistic only on rooted devices or with carefully constrained capability fallback.
- Android background execution is heavily constrained. “Autonomous” scan scheduling must be implemented using platform-compliant background primitives, foreground notifications where required, and explicit user control.
- Shipping upstream Nmap inside a product requires a licensing/compliance decision rather than an assumption.

### Key product risks identified early
1. **Capability gap on non-root devices**
   - Risk: users expect full Nmap behavior, but non-root Android devices cannot safely or legally expose every raw-packet feature.
   - Mitigation: implement explicit capability detection, disclose degraded modes, and separate rooted/non-root scan profiles.
2. **Binary distribution and update strategy**
   - Risk: app architecture depends on whether Nmap is bundled, externally provided, or remotely executed.
   - Mitigation: confirm product distribution model before coding the native execution layer.
3. **Autonomous execution limits**
   - Risk: Android may interrupt long-running work unless the app follows foreground/background execution rules.
   - Mitigation: use WorkManager or direct foreground-service patterns only where justified and user-visible.
4. **Scope inflation**
   - Risk: “all functionality” can expand into a full Nmap distro, scripting engine asset management, scan history, diffing, automation, export, notifications, and policy controls.
   - Mitigation: lock milestone-based acceptance criteria before implementation.

### Implementation stance
- I will not fabricate a fake Nmap engine in Kotlin.
- I will not claim full Nmap parity unless actual native execution support is present and verified.
- I will prioritize a production-ready Android architecture that can host real Nmap execution, surface capability limitations honestly, and support autonomous workflows in a platform-compliant way.

### Recommended first milestone
- Confirm execution/distribution model and target device class.
- Bootstrap the Android project with:
  - Kotlin + Jetpack Compose UI,
  - modular architecture,
  - scan profile domain model,
  - command validation layer,
  - execution abstraction for native tools (`nmap`, `ncat`, `nping`),
  - autonomous scheduler abstractions,
  - history/report storage,
  - unit tests for command construction and validation.

### Implementation work completed in this session
- I translated the agreed product direction into a real repository structure instead of a mockup:
  - Android client module
  - shared contract/validation module
  - remote executor backend module
- I deliberately made the Android app **honest by design**:
  - the local executor is represented but disabled,
  - remote execution is first-class,
  - automation, persistence, profiles, and history still function around that reality.
- I added a shared validation layer because security tooling cannot safely rely on ad-hoc string concatenation.
- I used `ProcessBuilder` with structured argv on the backend to avoid shell injection and then layered flag-policy restrictions on top of that.
- I added Android Keystore-backed encryption for the remote bearer token because “autonomous” scans are not useful if credential persistence is handled carelessly.

### Challenges encountered
1. **Sandbox tooling limitation**
   - The workspace does not currently have Java installed.
   - Consequence: I could not run Gradle, compile Android code, or execute JVM tests here.
   - Response: I stayed explicit about non-verification and avoided claiming build success.
2. **Wrapper bootstrapping without local Gradle**
   - Since Gradle was not installed, I could not generate wrapper files conventionally.
   - Response: I retrieved Gradle wrapper artifacts through GitHub instead of fabricating them.
3. **Full-functionality tension vs security-first design**
   - Raw expert-mode support is needed for broad Nmap compatibility, but unrestricted pass-through is dangerous on a remote executor.
   - Response: I implemented expert-argument tokenization plus a narrow denylist for file-output and process-exec behaviors.
4. **Non-root-first promise vs local execution reality**
   - A local-only implementation would either be misleading or severely limited.
   - Response: I codified hybrid routing and documented the open limitation instead of pretending parity exists.

### Design decisions that mattered
- I kept the module split small and justified: one Android app, one shared contract module, one backend module.
- I avoided adding Hilt, Retrofit, or other extra dependencies before they were necessary.
- I used Room and WorkManager because they directly satisfy persistence and autonomous scheduling requirements on Android.
- I kept command modeling generic enough to support `nmap`, `ncat`, and `nping` without inventing a fake replacement engine.

### Lessons so far
- On greenfield security-tooling apps, the hardest early problem is not UI; it is aligning platform constraints, licensing, and user expectations before implementation.
- Honest capability modeling is essential. A trustworthy security tool must clearly distinguish what it can actually run from what it can only plan or simulate.
- In mobile security tools, “full functionality” usually requires backend and policy design just as much as frontend work.
