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

### Additional implementation work completed after the initial bootstrap
- I extended the builder from a plain text argument field into a more governed workflow by adding structured Nmap controls and deriving the final CLI argument string deterministically.
- I added per-profile run delta summaries so repeated scans become more actionable instead of just producing isolated logs.
- I tightened the remote executor with optional target regex policies and capped stdout/stderr capture to reduce abuse and resource-risk on the host.

### Additional challenges encountered
1. **Structured controls vs open-ended CLI flexibility**
   - Risk: if structured controls and expert arguments both control the same flags, the generated command becomes ambiguous.
   - Response: I added conflict detection so managed Nmap flags must come from the structured layer, while genuinely extra flags stay in expert arguments.
2. **Meaningful diffing without full protocol-aware parsing**
   - Risk: a fake “diff” would be misleading if it claimed semantic understanding of Nmap output.
   - Response: I implemented honest delta summaries based on status, route, exit code, command preview, and captured output fingerprint changes.
3. **Remote executor memory safety**
   - Risk: unbounded process output can exhaust memory or degrade service quality.
   - Response: I switched to capped output capture with explicit truncation notes returned to the client.

### Additional lessons so far
- Structured UI controls are valuable even for expert tools when they generate a deterministic, auditable command line instead of hiding it.
- For security tooling, “better UX” often means fewer ambiguous states and more transparent policy enforcement.
- Change awareness matters: recurring scans become significantly more useful when the operator can immediately see whether the latest run materially differs from the previous one.
- Lightweight output parsing is useful, but it must be described honestly as heuristic unless the implementation is driven by a guaranteed structured output format.
- Dashboard insights become much more valuable when they are derived from saved run history and explicit parsed deltas instead of invented status labels.
- When a tool already has a documented structured output format, it is usually better engineering to capture and parse that format than to keep expanding fragile text heuristics. Nmap XML fits that pattern well.
- Once structured parsing exists, it is also important to preserve **capture integrity metadata**. Otherwise the UI can overstate confidence in partial/truncated results.
- Profile dashboards become more actionable when they combine configuration state, schedule cadence, and latest execution outcome instead of showing saved profiles as static objects.
- Execution history becomes far more useful for real operations once each run carries correlation metadata such as executor labels and request IDs; otherwise screenshots and copied excerpts are hard to reconcile with backend-side investigation.
- Static source review still matters when the sandbox cannot compile: in this pass, manual inspection exposed a duplicate `CommandPreview` object in the shared module that honest runtime-free verification had not previously surfaced.
- Capability reports are easy to over-trust unless the product tracks freshness. Marking them stale after settings edits is a small UX detail that materially improves operational honesty.
- Pre-run execution guidance is worth centralizing in shared logic rather than scattering ad-hoc warnings through Compose, because route assumptions and privilege caveats are domain rules, not just UI copy.
- Once report generation becomes operationally useful, clipboard-only export is not enough. Adding SAF/file-share paths keeps the app aligned with real Android operator workflows without pretending desktop-style unrestricted filesystem access exists.
- Request IDs only become genuinely useful when they appear on both success and failure paths. Propagating them into API error responses and optional backend audit logs closes that observability gap.
- Replacing a disabled local executor with a real stock-Android transport engine requires resisting the temptation to treat expert CLI text as magic. The safe path is to parse only a bounded, explicit subset and route everything else back toward the honest delegated-Nmap path.
- Pseudo-Nmap-compatible local output can still be worthwhile when it feeds a shared history/reporting pipeline, but only if the accompanying messages and guidance clearly state that the engine is connect-based and not a raw-packet parity layer.
- Once the product is viewed as a distributed scanning system, route labels alone become too weak. Shared executor capability profiles are a better abstraction because they let the UI describe what a node can do, how it is reached, and why a given scan should be delegated there.

## 2026-09-10 — Android-local Phase B service identification

### Why this batch was the right next step
- After adding shared executor capability profiles, the next highest-value improvement was not more UI polish; it was making the Android-local route slightly more useful without pretending it had raw-packet parity.
- `-sV` was already present in the builder controls, so the honest product gap was that Android-local planning still treated all service detection as impossible instead of distinguishing between curated local identification and real delegated Nmap version probing.

### What changed conceptually
- I kept the core rule intact: Android-local mode still must not impersonate full Nmap behavior.
- Instead of treating `-sV` as binary supported/unsupported, I modeled it as a **limited local capability**:
  - local execution can attempt curated protocol identification for selected TCP services,
  - delegated execution remains the better path when the operator expects fuller Nmap semantics.
- This led to an important routing refinement: AUTO mode can now acknowledge that a bounded local fallback exists while still preferring a delegated executor when available for better parity.

### Implementation notes
- The safest service-detection techniques for stock Android were application-layer and banner-oriented probes over normal sockets.
- I limited active probes to protocols where a small, explainable detector is defensible:
  - HTTP
  - TLS/HTTPS handshake inspection
  - SSH banners
  - banner-style SMTP/POP3/IMAP/FTP identification
- I also added a per-run ceiling for local service detection so a wide scan does not silently turn into an unbounded second wave of connection attempts.

### Trade-offs and constraints
- Local TLS identification is observational, not trust-establishing. For scanning usefulness, a permissive TLS handshake is more practical than relying on ordinary certificate trust validation, but the resulting metadata must not be misrepresented as authenticated identity.
- Local `-sV` still should not dominate AUTO routing when a delegated executor exists, because the delegated route offers semantics closer to actual Nmap version detection.
- Output formatting had to remain compatible with the existing shared parser/report pipeline, so the local executor emits conservative Nmap-like service/detail lines rather than inventing a brand-new report grammar.

### Lessons reinforced
- Capability modeling gets much better once support levels can express “limited but real” instead of forcing every feature into a yes/no bucket.
- For a distributed scanning product, route preference is not just about whether a task can run somewhere; it is also about which route best matches operator intent.
- Small, well-bounded protocol detectors are more trustworthy than broad claims of parity that the platform cannot honestly deliver.

## 2026-09-10 — Android-local Phase C fingerprint inference

### Why this batch mattered
- After phase-B local service identification, the next real functional gap was the `-O` toggle in the builder: it still implied a capability that Android-local execution could not honor honestly.
- The right fix was not to imitate Nmap TCP/IP fingerprinting. It was to add a clearly limited **evidence-based local inference** layer and make actual AUTO execution routing respect delegated preference when local support is only a fallback.

### What changed conceptually
- I separated **Android-local fingerprint inference** from real Nmap OS detection parity.
- In practice, that means local `-O` now stands for: "attempt a bounded, evidence-based family/device guess from socket-visible signals" rather than "perform raw-packet TCP/IP stack fingerprinting."
- I also fixed an architectural honesty bug: builder guidance already knew some profiles should prefer a delegated executor, but actual AUTO execution still picked local whenever local execution was merely possible. That mismatch is now removed.

### Implementation notes
- The local inferencer intentionally uses only evidence we can obtain honestly from stock Android execution:
  - open-port combinations
  - curated service names
  - service banners already captured during local `-sV`
  - HTTP/TLS metadata already observed during bounded local probing
- I kept the heuristic families broad on purpose:
  - Windows-family
  - Linux/Unix-family
  - Apple/Darwin-family
  - Android/Linux-family
  - embedded/network-appliance family
- The inferencer now emits Nmap-like but clearly labeled lines such as device type, OS details, and fingerprint evidence so saved-history parsing can surface the result without inventing a parallel report format.

### Trade-offs and constraints
- Local fingerprint inference is intentionally conservative. When evidence is weak or mixed, it now says so instead of fabricating a guess.
- The scoring model is simple and explainable, not exhaustive. That is preferable at this stage because overclaiming fingerprint accuracy would be worse than missing some opportunities.
- Adding the shared route selector was worthwhile because execution truth should not diverge between UI guidance and actual run dispatch.

### Lessons reinforced
- Once a product claims capability-aware routing, the runtime dispatcher must share the same decision logic as the UI planner or trust quickly erodes.
- Evidence-based inference is much safer to ship than faux parity when the underlying platform cannot expose the packet-level data that the upstream tool really depends on.
- Reusing the existing text-report pipeline is valuable, but only when the inserted lines remain explicit about their origin and confidence.

### Lessons so far
- On greenfield security-tooling apps, the hardest early problem is not UI; it is aligning platform constraints, licensing, and user expectations before implementation.
- Honest capability modeling is essential. A trustworthy security tool must clearly distinguish what it can actually run from what it can only plan or simulate.
- In mobile security tools, “full functionality” usually requires backend and policy design just as much as frontend work.

## 2026-09-10 — Delegated LAN-agent support

### Why this batch was the right next step
- After the Android-local phase-C work, the next best improvement was not to further stretch stock-Android probing. It was to improve the **delegation model** so the app can route scans toward the right authorized executor for the target topology.
- The product direction already treats scanning as distributed capability routing, so supporting a user-controlled LAN agent for private-network targets is more honest and more useful than pretending Wi-Fi presence gives the phone implicit packet-generation power.

### What changed conceptually
- I introduced explicit **target-topology classification** shared between Android and the backend.
- I separated two delegated roles in the Android client:
  - a **primary delegated executor** for general remote/Nmap-capable execution,
  - an optional **LAN agent** intended for RFC1918/link-local/loopback-style targets near the target network.
- I also promoted executor identity and target-scope policy into the shared contract so Android is not forced to assume every remote node has the same role.

### Implementation notes
- I kept the routing heuristic intentionally explainable: private-like targets bias toward the LAN agent, public-internet targets bias toward the general remote executor, and verified capability metadata can refine that choice.
- Android settings storage now preserves two independent delegated endpoints with distinct Keystore-encrypted bearer tokens, which avoids conflating trust boundaries.
- The backend can now advertise executor node kind, transport kind, allowed target scopes, and a topology summary while also rejecting execution requests whose targets fall outside the configured scope policy.
- I updated the settings/dashboard/builder surfaces so operators can inspect both delegated nodes instead of seeing a single undifferentiated “remote” slot.

### Trade-offs and constraints
- Runtime delegated selection in the Android repository currently relies primarily on configured role/topology intent rather than a fully persisted node registry with freshness history. That keeps the change bounded while still improving actual routing behavior.
- The topology classifier is intentionally conservative and mostly IP-shape based. Hostnames remain a softer category until an authorized executor resolves them in its own network context.
- I still could not run Gradle or Android builds here because JDK 17 remains unavailable, so this batch required careful static review and targeted shared tests rather than claiming compile verification.

### Lessons reinforced
- Once multiple executors exist, “remote configured” is too coarse. The UI and contracts need to express **which executor** is expected to run a scan and why.
- Capability freshness matters more when routing becomes topology-aware; otherwise the client can make confident-sounding but poorly grounded decisions.
- Security-sensitive mobile tooling benefits from modeling trust boundaries explicitly, even for something as simple as storing two different API tokens.

## 2026-09-10 — Persisted delegated capability snapshots and routing alignment

### Why this follow-up was necessary
- After the LAN-agent batch, there was still an architectural gap: the Compose UI could reason about delegated capability data in memory, but scheduled/background execution only had saved endpoints, not saved capability context.
- There was also a correctness bug in builder guidance: if some delegated executor was configured but none actually matched the current target topology, the builder could still sound more remote-ready than the runtime really was.

### What changed conceptually
- I treated **last verified delegated capability data** as part of the saved execution environment, not as throwaway UI state.
- I also tightened the rule that guidance and runtime should not disagree about whether a compatible delegated route really exists for the current targets.

### Implementation notes
- The Android settings store now persists per-slot delegated capability snapshots for:
  - the primary delegated executor
  - the LAN agent
- Those snapshots are automatically invalidated when the saved endpoint URL or token changes, which avoids silently applying stale policy/tool metadata to a different executor.
- A shared app-level delegated-executor resolver now bridges:
  - saved endpoint settings,
  - cached capability metadata,
  - target-topology routing heuristics.
- The ViewModel loads cached delegated capability snapshots on startup, while the repository reuses them during scheduled/manual execution when choosing the delegated endpoint.

### Trade-offs and constraints
- I intentionally kept snapshot persistence scoped to **saved settings** only. Manual capability refreshes against unsaved edits still update the current screen, but they are not treated as durable execution policy for automation.
- Snapshot age is preserved, but there is still no time-based expiry policy yet; the product currently treats staleness primarily as “edited since refresh,” not “older than N hours.”
- Because JDK 17 is still unavailable here, I relied on static review and incremental shared-test additions rather than claiming Android/Gradle verification.

### Lessons reinforced
- In a scheduled security tool, volatile UI state is not enough; routing-critical capability information needs a persistence strategy.
- Configuration validity is broader than URL syntax. Capability caches must also be invalidated when authentication context changes.
- The more the product promises capability-aware execution, the more important it becomes to make planner language conservative whenever topology/policy compatibility is unresolved.

## 2026-09-10 — Richer structured Nmap XML result modeling

### Why this batch was the right next step
- After stabilizing delegated routing, the next highest-value improvement was to make saved results more operationally useful.
- The app was already capturing structured Nmap XML, but it still reduced most runs to open-port rows and a small set of highlights. That left real upstream information like OS matches, NSE script output, uptime, and traceroute context underused.

### What changed conceptually
- I kept the core honesty rule: the app still is not claiming deeper scan capability than the executor actually provided.
- Instead, I improved how the client **models and surfaces structured results already returned by Nmap**.
- This is a safer and more production-aligned way to add value than inventing more heuristics, because the data comes from Nmap's actual XML schema rather than from fragile text scraping alone.

### Implementation notes
- I extended the shared result model with:
  - per-host detail blocks
  - script-result summaries
- The structured XML parser now extracts:
  - host addresses and alternative names
  - OS-match and OS-class hints
  - uptime and network-distance context
  - host/port/pre/post script outputs
  - traceroute summaries
  - richer service-detail strings including some service metadata and CPE data when present
- I also added an explicit warning path for malformed/unparseable XML so the fallback to heuristic text parsing is visible rather than silent.
- Android history/reporting now renders those richer parsed structures so the new model is actually usable, not just stored in memory.

### Trade-offs and constraints
- I intentionally summarized complex XML subtrees into operator-friendly lines rather than mirroring the entire Nmap DTD in the app model. That keeps the UI/reporting practical without pretending to be a full Zenmap-class XML explorer.
- Multiline script outputs are normalized into compact snippets for history/report screens, because raw NSE output can be very large and noisy on mobile.
- As with prior batches, I still could not run Gradle/JVM verification here because JDK 17 is unavailable in this sandbox.

### Lessons reinforced
- When an upstream tool already provides a structured schema, product quality usually improves more by modeling that schema better than by layering on increasingly ambitious text heuristics.
- Good mobile reporting often depends on summarization discipline: preserving high-value evidence without dumping every raw field into the first screen.
- Secure XML parsing is only half the job; operators also need explicit visibility when the structured path failed and the product had to fall back.
