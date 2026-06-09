//! `jitgen doctor` — probe the environment and report toolchain / sandbox / provider readiness.
//!
//! Doctor runs only jitgen's own fixed diagnostic commands (e.g. `git --version`) with constant
//! argv — never untrusted repo input — so it does not need the sandbox. Per ADR-0009 it reports,
//! for each first-class language, whether a *native* toolchain exists; missing native toolchains are
//! covered by the containerized sandbox backend in CI.

use jitgen_report::sanitize_line;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Per-probe wall-clock timeout. Diagnostic commands are jitgen's own fixed argv, but we still bound
/// them defensively (F2/S1 review #1).
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Single-line cap for a tool's name/version cell in the human report. A real `--version` first line
/// is short; this bounds a hostile tool's flood while leaving genuine versions intact.
const TOOL_FIELD_CAP: usize = 120;

/// Availability of a single external tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolStatus {
    /// Logical name (e.g. `git`, `pytest`).
    pub name: String,
    /// Whether the tool ran successfully.
    pub available: bool,
    /// First line of version output, if available.
    pub version: Option<String>,
}

/// Per-language toolchain availability (ADR-0009: native vs containerized).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LanguageStatus {
    /// Language id.
    pub language: String,
    /// Whether a native toolchain is present on this host.
    pub native: bool,
    /// Human-readable note (native / container / skipped).
    pub note: String,
}

/// Full doctor report (serializable for `--format json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// jitgen version.
    pub jitgen_version: String,
    /// Data-contract schema version.
    pub schema_version: u32,
    /// Host OS.
    pub os: String,
    /// External tools probed.
    pub tools: Vec<ToolStatus>,
    /// First-class language readiness.
    pub languages: Vec<LanguageStatus>,
    /// Selected sandbox tier (`os-sandbox` / `container` / `none`).
    pub sandbox_tier: String,
    /// Explanation of the sandbox selection (incl. fail-closed warning).
    pub sandbox_note: String,
    /// Detected container runtime, if any.
    pub container_runtime: Option<String>,
    /// Resolved state root path.
    pub state_root: String,
    /// Active LLM provider description.
    pub provider: String,
}

impl DoctorReport {
    /// Whether all hard prerequisites are present (currently: `git`).
    pub fn prerequisites_ok(&self) -> bool {
        self.tool_available("git")
    }

    fn tool_available(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t.name == name && t.available)
    }

    /// Render a human-readable report.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "jitgen {} (data-contract v{}) — environment report\n",
            self.jitgen_version, self.schema_version
        ));
        out.push_str(&format!("OS: {}\n\nTools:\n", self.os));
        for t in &self.tools {
            let mark = if t.available { "ok  " } else { "MISS" };
            // `version` is the first line of an external tool's `--version` output — doctor probes
            // whatever `git`/`rustc`/`node`/`docker` is first on the operator's PATH, which may be
            // hostile. `probe` only trims surrounding whitespace, leaving mid-line ESC/CSI/OSC and CR
            // intact, and this human report prints straight to the terminal (cli.rs) with no further
            // sanitizer — unlike the JSON path (serde-encoded) and every other CLI terminal sink (which
            // use `safe_for_terminal`). Route the version (and defensively the name) through the report
            // crate's single-line sanitizer so a malicious tool binary can't recolor the terminal, move
            // the cursor, set the window title, or forge a fake row. Mirrors `analyze`'s render_human.
            let name = sanitize_line(&t.name, TOOL_FIELD_CAP);
            let ver = sanitize_line(t.version.as_deref().unwrap_or("-"), TOOL_FIELD_CAP);
            out.push_str(&format!("  [{mark}] {name:<10} {ver}\n"));
        }
        out.push_str("\nLanguages (native toolchain; CI uses containers otherwise — ADR-0009):\n");
        for l in &self.languages {
            let mark = if l.native { "native" } else { "no-native" };
            out.push_str(&format!("  {:<11} {:<10} {}\n", l.language, mark, l.note));
        }
        out.push_str(&format!(
            "\nSandbox tier: {}\n  {}\n",
            self.sandbox_tier, self.sandbox_note
        ));
        if let Some(rt) = &self.container_runtime {
            out.push_str(&format!("Container runtime: {rt}\n"));
        }
        out.push_str(&format!("State root: {}\n", self.state_root));
        out.push_str(&format!("LLM provider: {}\n", self.provider));
        if !self.prerequisites_ok() {
            out.push_str("\nWARNING: git not found — jitgen requires git to operate.\n");
        }
        out
    }
}

/// Opt-in strict CI-readiness requirements for `jitgen doctor --require-*` (GP8). Doctor's default is a
/// 0/1 probe that gates only on `git`; these turn specific readiness facts into the exit code so a CI
/// preflight fails *before* a run, not mid-run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StrictRequirements {
    /// Require an *isolating* sandbox tier (`os-sandbox`/`container`) — or, with
    /// [`Self::unsafe_local_execution`], explicit acceptance of the constrained-local tier.
    pub require_sandbox: bool,
    /// Require a real (non-mock) LLM provider whose API key is present.
    pub require_real_llm: bool,
    /// The operator passed `--unsafe-local-execution`, accepting the constrained-local tier as the
    /// execution path ("the container is the sandbox"). Lets [`Self::require_sandbox`] pass with no
    /// detected isolating tier — but doctor still flags it as the weak boundary it is (Codex #11): the
    /// constrained-local tier has no kernel-enforced network/file isolation (ADR-0003).
    pub unsafe_local_execution: bool,
}

/// Outcome of a strict `doctor` evaluation. `failures` (non-empty ⇒ non-zero exit) lists unmet
/// requirements; `notes` carries advisory context — notably that a `--require-sandbox` pass rests on
/// the *weak* constrained-local tier, not a real isolating sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrictVerdict {
    /// Unmet requirements. Empty ⇒ all requested strict requirements are satisfied.
    pub failures: Vec<String>,
    /// Advisory notes that do not gate (e.g. "passed on constrained-local — not a real sandbox").
    pub notes: Vec<String>,
}

impl DoctorReport {
    /// Evaluate strict CI-readiness against opt-in `--require-*` requirements. `real_llm_ready` is
    /// supplied by the caller (the report carries only the provider *description* string, not the
    /// resolved config) — compute it with [`real_llm_ready`]. The base `git` prerequisite is NOT
    /// re-checked here; the caller still gates the exit code on [`Self::prerequisites_ok`] too.
    pub fn strict_verdict(&self, req: &StrictRequirements, real_llm_ready: bool) -> StrictVerdict {
        let mut v = StrictVerdict::default();
        if req.require_sandbox {
            if self.sandbox_tier != "none" {
                // A real isolating tier (os-sandbox/container) will be auto-selected — the strong
                // boundary. jitgen prefers it even if --unsafe-local-execution is also passed.
            } else if req.unsafe_local_execution {
                v.notes.push(
                    "--require-sandbox: no isolating tier detected; passing because \
                     --unsafe-local-execution accepts the constrained-local tier. That tier has NO \
                     kernel-enforced network/file isolation and relies on the surrounding ephemeral \
                     container for it (ADR-0003) — it is NOT a real isolating sandbox. Only safe \
                     inside a throwaway, jitgen-owned container."
                        .to_string(),
                );
            } else {
                v.failures.push(
                    "--require-sandbox: no isolating sandbox tier (os-sandbox/container) detected and \
                     --unsafe-local-execution not set — jitgen would refuse to execute tests \
                     (fail-closed). Install bubblewrap, run inside the jitgen container, or pass \
                     --unsafe-local-execution if this IS a throwaway container."
                        .to_string(),
                );
            }
        }
        if req.require_real_llm && !real_llm_ready {
            v.failures.push(
                "--require-real-llm: no real LLM provider ready — needs --real-llm plus a trusted \
                 provider whose API-key env var is set (the default is the offline mock). See \
                 docs/ci.md → Real LLM providers."
                    .to_string(),
            );
        }
        v
    }
}

/// Whether the resolved provider is ready for REAL LLM calls: a non-mock provider whose API-key env var
/// is set (or a keyless `local` provider). Mirrors [`describe_provider`]'s master switch + key check, so
/// `doctor --require-real-llm`'s verdict agrees with what doctor *reports*. Reads only key *presence*,
/// never the value. Note: for a keyless `local` provider this confirms only that one is *configured* —
/// it does NOT probe the endpoint, so a `--require-real-llm` pass means "a real provider is wired", not
/// "the server is reachable".
#[must_use = "the returned readiness feeds strict_verdict's `real_llm_ready` arg; dropping it skips the --require-real-llm check"]
pub fn real_llm_ready(provider: &jitgen_core::ProviderConfig) -> bool {
    if jitgen_llm::provider_is_mock(provider) {
        return false; // mock in force (kind == Mock or real_llm off) ⇒ not ready for real calls
    }
    match jitgen_llm::provider_key_env(provider) {
        Some(env) => std::env::var(&env).is_ok_and(|v| !v.trim().is_empty()),
        None => true, // a `local` provider needs no key
    }
}

/// A directory safe to run diagnostic probes from — NEVER the target repo, so tools cannot pick up
/// repo-relative config or modules (F2/S1 review #1).
fn safe_probe_cwd() -> std::path::PathBuf {
    std::env::temp_dir()
}

/// Minimal, non-secret environment for probes: only `PATH` (to find tools) and `HOME` (some tools
/// need it). Tokens/credentials in the ambient env are NOT propagated.
fn minimal_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    for key in ["PATH", "HOME"] {
        if let Ok(val) = std::env::var(key) {
            env.push((key.to_string(), val));
        }
    }
    env
}

/// Probe a command with a hardened invocation (safe cwd, cleared env + minimal allowlist, no stdin,
/// a wall-clock timeout, killed on expiry). Returns `(ran_successfully, first_output_line)`.
fn probe(program: &str, args: &[&str]) -> (bool, Option<String>) {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(safe_probe_cwd())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in minimal_env() {
        cmd.env(k, v);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return (false, None), // tool not found / cannot spawn
    };

    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => return (false, None),
        }
    };
    let Some(status) = status else {
        return (false, Some("(probe timed out)".to_string()));
    };

    // Output is tiny (a version line); reading after exit cannot deadlock.
    let mut buf = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_end(&mut buf);
    }
    if buf.is_empty() {
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_end(&mut buf); // some tools (java) print to stderr
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().next().unwrap_or("").trim().to_string();
    (
        status.success(),
        if line.is_empty() { None } else { Some(line) },
    )
}

fn tool(name: &str, program: &str, args: &[&str]) -> ToolStatus {
    let (ok, version) = probe(program, args);
    ToolStatus {
        name: name.to_string(),
        available: ok,
        version: if ok { version } else { None },
    }
}

fn lang_note(native: bool, container: &Option<String>) -> String {
    if native {
        "native toolchain present".to_string()
    } else if let Some(rt) = container {
        format!("no native toolchain; runs via {rt} container (ADR-0009)")
    } else {
        "no native toolchain and no container; e2e skipped on this host".to_string()
    }
}

/// Map the detected isolating backends (strongest-first, from [`jitgen_sandbox::detect`]) plus whether a
/// container *client* was seen in the tool probe to the reported `(sandbox_tier, sandbox_note,
/// container_runtime)`. Pure, so the tier decision — in particular the "container client installed but no
/// usable backend ⇒ none" case that GP8's `--require-sandbox` exists to catch — is deterministically
/// unit-testable without the live host environment. `detect` lists backends strongest-first and never
/// returns the constrained-local tier (fail-closed; ADR-0003/0010).
fn classify_sandbox(
    detected: &[jitgen_sandbox::Backend],
    container_client_present: bool,
    os: &str,
) -> (String, String, Option<String>) {
    use jitgen_sandbox::Tier;
    // The container runtime is reported whenever a container backend is usable, even if a stronger
    // OS-sandbox tier is the one actually selected (the language notes still want it).
    let container_runtime = detected
        .iter()
        .find(|b| b.tier() == Tier::Container)
        .map(|b| b.id().to_string());
    let (tier, note) = match detected.first().map(|b| (b.tier(), b.id())) {
        Some((Tier::OsSandbox, id)) => (
            "os-sandbox".to_string(),
            format!("OS sandbox available ({id}) on {os}"),
        ),
        Some((Tier::Container, id)) => (
            "container".to_string(),
            format!("using {id} container backend"),
        ),
        // `detect` never returns the constrained-local tier; fold it into "none" defensively.
        Some((Tier::ConstrainedLocal, _)) | None => {
            // Distinguish "a container client is installed but no isolating backend is usable" (its
            // daemon is unreachable/unauthorized/misconfigured, or it is off the trusted launcher path
            // — a common CI misconfig) from "nothing at all", so a failed `--require-sandbox` points
            // at the real problem.
            let note = if container_client_present {
                "FAIL-CLOSED: a container runtime client is installed but no isolating backend is \
                 usable — its daemon is not usable (unreachable, unauthorized, or misconfigured, \
                 e.g. DOCKER_HOST/permissions) or the client is not on a trusted launcher path, so \
                 untrusted tests cannot run in a container. Start/authorize the daemon, install an \
                 OS sandbox (bubblewrap), or pass --unsafe-local-execution if this IS a throwaway \
                 container (ADR-0003/0010)"
            } else {
                "FAIL-CLOSED: no OS sandbox or container available; untrusted execution is refused \
                 unless the trusted --unsafe-local-execution flag is passed (ADR-0003/0010)"
            };
            ("none".to_string(), note.to_string())
        }
    };
    (tier, note, container_runtime)
}

/// Run all probes and assemble a [`DoctorReport`].
pub fn run_doctor(state_root: &str, provider: &str) -> DoctorReport {
    let tools = vec![
        tool("git", "git", &["--version"]),
        tool("rustc", "rustc", &["--version"]),
        tool("cargo", "cargo", &["--version"]),
        tool("bazel", "bazel", &["--version"]),
        tool("node", "node", &["--version"]),
        tool("npm", "npm", &["--version"]),
        tool("pnpm", "pnpm", &["--version"]),
        tool("yarn", "yarn", &["--version"]),
        tool("bun", "bun", &["--version"]),
        tool("python3", "python3", &["-I", "--version"]),
        // Detect pytest WITHOUT importing it: isolated mode (`-I`, no CWD on sys.path) + read the
        // installed dist metadata only. Never executes pytest/conftest from a hostile repo.
        tool(
            "pytest",
            "python3",
            &[
                "-I",
                "-c",
                "import importlib.metadata as m,sys;sys.stdout.write(m.version('pytest'))",
            ],
        ),
        tool("java", "java", &["-version"]),
        tool("maven", "mvn", &["--version"]),
        tool("gradle", "gradle", &["--version"]),
        tool("docker", "docker", &["--version"]),
        tool("podman", "podman", &["--version"]),
    ];
    let have = |n: &str| tools.iter().any(|t| t.name == n && t.available);
    let os = std::env::consts::OS;

    // Sandbox tier: derive it from the SAME detection the run path uses (`jitgen_sandbox::detect`),
    // not a parallel best-effort probe. `detect` reports only backends that are actually *usable* —
    // for Docker/Podman that means the daemon answered (`docker version`) and the launcher resolved
    // from a trusted bin dir — so doctor's tier (and `doctor --require-sandbox`, GP8) matches the tier
    // `jitgen run` AUTO-selects (what CI uses), instead of passing on a mere `docker --version` client
    // check that would then fail-closed mid-run. (A trusted config that PINS a specific backend is not
    // modeled here — doctor reports the strongest *available* tier.) The pure mapping lives in
    // `classify_sandbox` so the tier decision is deterministically testable off the live environment.
    let detected = jitgen_sandbox::detect();
    let (sandbox_tier, sandbox_note, container) =
        classify_sandbox(&detected, have("docker") || have("podman"), os);

    let languages = vec![
        LanguageStatus {
            language: "rust".to_string(),
            native: have("cargo"),
            note: lang_note(have("cargo"), &container),
        },
        LanguageStatus {
            language: "typescript".to_string(),
            native: have("node"),
            note: lang_note(have("node"), &container),
        },
        LanguageStatus {
            language: "python".to_string(),
            native: have("python3") && have("pytest"),
            note: lang_note(have("python3") && have("pytest"), &container),
        },
        LanguageStatus {
            language: "java".to_string(),
            native: have("java") && (have("maven") || have("gradle")),
            note: lang_note(
                have("java") && (have("maven") || have("gradle")),
                &container,
            ),
        },
    ];

    DoctorReport {
        jitgen_version: jitgen_core::version().to_string(),
        schema_version: jitgen_core::SCHEMA_VERSION,
        os: os.to_string(),
        tools,
        languages,
        sandbox_tier,
        sandbox_note,
        container_runtime: container,
        state_root: state_root.to_string(),
        provider: provider.to_string(),
    }
}

/// One-line description of the EFFECTIVE LLM provider for `doctor`, reporting API-key-env PRESENCE
/// only (never the value). Mirrors `jitgen_llm::make_provider`'s master switch: the mock is in force
/// unless `real_llm` is on AND a non-mock kind is selected.
pub fn describe_provider(provider: &jitgen_core::ProviderConfig) -> String {
    use jitgen_core::ProviderKind;
    // Same master switch as `make_provider`, via the shared helper (no drift).
    if jitgen_llm::provider_is_mock(provider) {
        return "mock (default; offline & deterministic — set a trusted provider and pass --real-llm \
                for real generation)"
            .to_string();
    }
    let kind = match provider.kind {
        ProviderKind::Anthropic => "anthropic",
        ProviderKind::OpenAiCompatible => "openai-compatible",
        ProviderKind::Local => "local",
        // Unreachable by contract (`provider_is_mock` returns true for Mock and is handled above), but
        // a diagnostic command must never hard-panic in release — degrade to a label instead of
        // `unreachable!`. The `debug_assert!` still surfaces a bypassed guard loudly in dev/CI.
        ProviderKind::Mock => {
            debug_assert!(
                false,
                "describe_provider reached Mock; provider_is_mock guard was bypassed"
            );
            "mock"
        }
    };
    let model = provider.model.as_deref().unwrap_or("(provider default)");
    let key = match jitgen_llm::provider_key_env(provider) {
        Some(env) => {
            let present = std::env::var(&env).is_ok_and(|v| !v.trim().is_empty());
            if present {
                format!("{env} is set")
            } else {
                format!("{env} NOT set — export it before running")
            }
        }
        None => "no API key required".to_string(),
    };
    format!("{kind} (real_llm enabled; model: {model}; {key})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{ProviderConfig, ProviderKind};

    #[test]
    fn describe_provider_reports_mock_then_key_presence() {
        // real_llm off ⇒ effective mock, regardless of kind.
        let off = ProviderConfig {
            kind: ProviderKind::Anthropic,
            real_llm: false,
            ..Default::default()
        };
        assert!(describe_provider(&off).starts_with("mock"));

        let env = "JITGEN_TEST_DOCTOR_KEY";
        std::env::remove_var(env);
        let real = ProviderConfig {
            kind: ProviderKind::Anthropic,
            real_llm: true,
            api_key_env: Some(env.into()),
            ..Default::default()
        };
        let absent = describe_provider(&real);
        assert!(absent.contains("anthropic") && absent.contains("NOT set"));

        std::env::set_var(env, "sk-secret");
        let present = describe_provider(&real);
        std::env::remove_var(env);
        // Reports presence, never the value.
        assert!(present.contains("is set") && !present.contains("sk-secret"));
    }

    // No dedicated test for `describe_provider`'s `ProviderKind::Mock` arm: `provider_is_mock` returns
    // true for every Mock config and is handled by the early return above, so the arm is unreachable
    // from any caller (tests included) without a bypass seam — its `debug_assert!` is a defensive
    // tripwire, not testable behavior. The reachable mock path is covered by the test above.

    fn report_with(tools: Vec<ToolStatus>) -> DoctorReport {
        DoctorReport {
            jitgen_version: "0.1.0".into(),
            schema_version: 1,
            os: "macos".into(),
            tools,
            languages: vec![LanguageStatus {
                language: "rust".into(),
                native: true,
                note: "native toolchain present".into(),
            }],
            sandbox_tier: "container".into(),
            sandbox_note: "using docker container backend".into(),
            container_runtime: Some("docker".into()),
            state_root: "/tmp/state".into(),
            provider: "mock (default)".into(),
        }
    }

    #[test]
    fn prerequisites_require_git() {
        let with_git = report_with(vec![ToolStatus {
            name: "git".into(),
            available: true,
            version: Some("git 2.x".into()),
        }]);
        assert!(with_git.prerequisites_ok());

        let without = report_with(vec![ToolStatus {
            name: "git".into(),
            available: false,
            version: None,
        }]);
        assert!(!without.prerequisites_ok());
        assert!(without.render_human().contains("git not found"));
    }

    #[test]
    fn render_human_sanitizes_hostile_tool_version() {
        // A malicious `git`/`rustc`/`node`/`docker` earlier on the operator's PATH can emit ANSI/CR in
        // its `--version` line; doctor's human report prints straight to the terminal, so the version
        // (and defensively the name) must be control-stripped first (mirrors the CLI's other sinks).
        let r = report_with(vec![ToolStatus {
            name: "git".into(),
            available: true,
            version: Some("\x1b[2Jx\rPWNED".into()),
        }]);
        let out = r.render_human();
        assert!(
            !out.contains('\x1b'),
            "ESC leaked into terminal output: {out:?}"
        );
        assert!(
            !out.contains('\r'),
            "CR leaked into terminal output: {out:?}"
        );
        // The inert remainder still renders, so the report stays useful.
        assert!(out.contains("PWNED"), "{out:?}");
    }

    #[test]
    fn report_roundtrips_json() {
        let r = report_with(vec![ToolStatus {
            name: "git".into(),
            available: true,
            version: Some("git 2.x".into()),
        }]);
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<DoctorReport>(&j).unwrap(), r);
    }

    #[test]
    fn real_doctor_produces_wellformed_report() {
        // Environment-agnostic: probes the real environment but asserts only structural
        // well-formedness, NOT presence of specific tools (the Bazel test sandbox has a restricted
        // PATH, so git/rustc may be absent there — doctor must handle that gracefully).
        let r = run_doctor("/tmp/jitgen-state", "mock (default)");
        assert!(r.tools.iter().any(|t| t.name == "git"));
        assert_eq!(r.languages.len(), 4);
        assert!(r.languages.iter().any(|l| l.language == "rust"));
        assert!(["os-sandbox", "container", "none"].contains(&r.sandbox_tier.as_str()));
        assert!(!r.render_human().is_empty());
    }

    #[test]
    fn run_doctor_sandbox_fields_are_internally_consistent() {
        // Smoke check on the assembled report's sandbox fields — NOT a second detection comparison
        // (the deterministic regression guard for the `--require-sandbox` gate lives in
        // `classify_sandbox_maps_detected_backends_to_tier`, which is host-independent). Here we only
        // assert internal consistency of one real `run_doctor` call: a "container" tier must name the
        // usable runtime. (The converse does NOT hold — a host can expose both an OS sandbox, the
        // selected tier, and a usable container daemon, so `container_runtime` may be set on any tier.)
        let r = run_doctor("/tmp/jitgen-state", "mock");
        if r.sandbox_tier == "container" {
            assert!(
                r.container_runtime.is_some(),
                "container tier must name a runtime"
            );
        }
    }

    #[test]
    fn classify_sandbox_maps_detected_backends_to_tier() {
        use jitgen_sandbox::Backend;

        // THE BUG CASE (deterministic, host-independent): a container CLIENT is present but
        // `detect()` found no USABLE backend (daemon down / off the trusted path) ⇒ tier "none", NOT
        // "container". The pre-fix client-only `docker --version` probe reported "container" here,
        // letting `--require-sandbox` pass on a runner that would then fail-closed mid-run (GP8).
        let (tier, note, rt) = classify_sandbox(&[], true, "linux");
        assert_eq!(
            tier, "none",
            "client present + no usable backend must be 'none'"
        );
        assert_eq!(rt, None);
        assert!(
            note.contains("client is installed") && note.contains("daemon"),
            "the daemon-unusable note should explain the misconfig: {note}"
        );

        // Nothing at all ⇒ "none" with the plain fail-closed note (no client/daemon hint).
        let (tier, note, rt) = classify_sandbox(&[], false, "linux");
        assert_eq!(tier, "none");
        assert_eq!(rt, None);
        assert!(
            note.contains("no OS sandbox or container") && !note.contains("client is installed")
        );

        // A usable container backend ⇒ "container", naming the runtime.
        let (tier, _n, rt) = classify_sandbox(&[Backend::Docker], true, "linux");
        assert_eq!(tier, "container");
        assert_eq!(rt.as_deref(), Some("docker"));

        // An OS sandbox wins even when a usable container is ALSO present; the selected tier is
        // os-sandbox, but container_runtime is still reported (for the language notes).
        let (tier, _n, rt) = classify_sandbox(&[Backend::Bwrap, Backend::Docker], true, "linux");
        assert_eq!(tier, "os-sandbox");
        assert_eq!(rt.as_deref(), Some("docker"));

        // os-sandbox only ⇒ no container_runtime.
        let (tier, note, rt) = classify_sandbox(&[Backend::SandboxExec], false, "macos");
        assert_eq!(tier, "os-sandbox");
        assert_eq!(rt, None);
        assert!(note.contains("macos"));
    }

    /// A report carrying a chosen sandbox tier (git present), for strict-verdict tests.
    fn report_tier(tier: &str) -> DoctorReport {
        let mut r = report_with(vec![ToolStatus {
            name: "git".into(),
            available: true,
            version: Some("git 2.x".into()),
        }]);
        r.sandbox_tier = tier.to_string();
        r
    }

    #[test]
    fn strict_verdict_is_empty_when_nothing_is_required() {
        // No --require-* flags ⇒ no strict failures, no notes, whatever the environment looks like.
        let v = report_tier("none").strict_verdict(&StrictRequirements::default(), false);
        assert!(v.failures.is_empty() && v.notes.is_empty());
    }

    #[test]
    fn require_sandbox_passes_on_a_real_isolating_tier() {
        for tier in ["os-sandbox", "container"] {
            let req = StrictRequirements {
                require_sandbox: true,
                ..Default::default()
            };
            let v = report_tier(tier).strict_verdict(&req, false);
            assert!(
                v.failures.is_empty(),
                "tier {tier} should satisfy --require-sandbox"
            );
            assert!(
                v.notes.is_empty(),
                "a real isolating tier needs no weak-boundary note"
            );

            // A real isolating tier wins even when --unsafe-local-execution is ALSO passed: still no
            // failure and — critically — no weak-boundary note (the note is only for the fallback).
            let req_unsafe = StrictRequirements {
                require_sandbox: true,
                unsafe_local_execution: true,
                ..Default::default()
            };
            let v2 = report_tier(tier).strict_verdict(&req_unsafe, false);
            assert!(
                v2.failures.is_empty() && v2.notes.is_empty(),
                "tier {tier} + --unsafe-local-execution must pass with no weak-boundary note"
            );
        }
    }

    #[test]
    fn require_sandbox_fails_on_bare_constrained_local() {
        // No isolating tier AND no --unsafe-local-execution ⇒ jitgen would refuse to run (fail-closed),
        // so the strict preflight must fail (the whole point of GP8).
        let req = StrictRequirements {
            require_sandbox: true,
            unsafe_local_execution: false,
            ..Default::default()
        };
        let v = report_tier("none").strict_verdict(&req, false);
        assert_eq!(v.failures.len(), 1);
        assert!(v.failures[0].contains("--unsafe-local-execution not set"));
        assert!(v.notes.is_empty());
    }

    #[test]
    fn require_sandbox_passes_constrained_local_with_unsafe_but_flags_the_weak_boundary() {
        // Codex #11: --unsafe-local-execution lets --require-sandbox pass on constrained-local, but
        // doctor must distinguish it from a real sandbox — so it passes WITH a weak-boundary note.
        let req = StrictRequirements {
            require_sandbox: true,
            unsafe_local_execution: true,
            ..Default::default()
        };
        let v = report_tier("none").strict_verdict(&req, false);
        assert!(
            v.failures.is_empty(),
            "unsafe-local-execution accepts constrained-local"
        );
        assert_eq!(v.notes.len(), 1);
        assert!(v.notes[0].contains("constrained-local") && v.notes[0].contains("NOT a real"));
    }

    #[test]
    fn require_real_llm_gates_on_readiness() {
        let req = StrictRequirements {
            require_real_llm: true,
            ..Default::default()
        };
        // Not ready ⇒ a failure that points at --real-llm + a configured key.
        let not_ready = report_tier("container").strict_verdict(&req, false);
        assert_eq!(not_ready.failures.len(), 1);
        assert!(not_ready.failures[0].contains("--real-llm"));
        // Ready ⇒ no failure.
        let ready = report_tier("container").strict_verdict(&req, true);
        assert!(ready.failures.is_empty());
    }

    #[test]
    fn strict_requirements_compose() {
        // Both flags, both unmet (tier none, real-llm not ready, no unsafe) ⇒ two failures.
        let req = StrictRequirements {
            require_sandbox: true,
            require_real_llm: true,
            unsafe_local_execution: false,
        };
        let v = report_tier("none").strict_verdict(&req, false);
        assert_eq!(v.failures.len(), 2);
    }

    #[test]
    fn real_llm_ready_mirrors_the_provider_master_switch() {
        use jitgen_core::{ProviderConfig, ProviderKind};
        // Mock / real_llm off ⇒ never ready.
        assert!(!real_llm_ready(&ProviderConfig {
            kind: ProviderKind::Anthropic,
            real_llm: false,
            ..Default::default()
        }));
        // A `local` provider needs no key ⇒ ready when real_llm is on.
        assert!(real_llm_ready(&ProviderConfig {
            kind: ProviderKind::Local,
            real_llm: true,
            base_url: Some("http://127.0.0.1:11434".into()),
            ..Default::default()
        }));
        // Real provider: ready iff its API-key env var is set and non-empty.
        let env = "JITGEN_TEST_REQUIRE_REAL_LLM_KEY";
        std::env::remove_var(env);
        let real = ProviderConfig {
            kind: ProviderKind::Anthropic,
            real_llm: true,
            api_key_env: Some(env.into()),
            ..Default::default()
        };
        assert!(!real_llm_ready(&real), "absent key ⇒ not ready");
        std::env::set_var(env, "sk-secret");
        assert!(real_llm_ready(&real), "present key ⇒ ready");
        std::env::set_var(env, "   ");
        assert!(!real_llm_ready(&real), "blank key ⇒ not ready");
        std::env::remove_var(env);
    }
}
