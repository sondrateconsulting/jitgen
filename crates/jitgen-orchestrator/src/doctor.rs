//! `jitgen doctor` — probe the environment and report toolchain / sandbox / provider readiness.
//!
//! Doctor runs only jitgen's own fixed diagnostic commands (e.g. `git --version`) with constant
//! argv — never untrusted repo input — so it does not need the sandbox. Per ADR-0009 it reports,
//! for each first-class language, whether a *native* toolchain exists; missing native toolchains are
//! covered by the containerized sandbox backend in CI.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Per-probe wall-clock timeout. Diagnostic commands are jitgen's own fixed argv, but we still bound
/// them defensively (F2/S1 review #1).
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

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
            let ver = t.version.as_deref().unwrap_or("-");
            out.push_str(&format!("  [{mark}] {:<10} {ver}\n", t.name));
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

    let container = if have("docker") {
        Some("docker".to_string())
    } else if have("podman") {
        Some("podman".to_string())
    } else {
        None
    };

    let os = std::env::consts::OS;
    let os_sandbox = match os {
        "linux" => probe("bwrap", &["--version"]).0 || probe("firejail", &["--version"]).0,
        "macos" => std::path::Path::new("/usr/bin/sandbox-exec").exists(),
        _ => false,
    };
    let (sandbox_tier, sandbox_note) = if os_sandbox {
        (
            "os-sandbox".to_string(),
            format!("OS sandbox available on {os}"),
        )
    } else if let Some(rt) = &container {
        (
            "container".to_string(),
            format!("using {rt} container backend"),
        )
    } else {
        (
            "none".to_string(),
            "FAIL-CLOSED: no OS sandbox or container available; untrusted execution is refused \
             unless the trusted --unsafe-local-execution flag is passed (ADR-0003/0010)"
                .to_string(),
        )
    };

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
        ProviderKind::Mock => unreachable!("mock handled above"),
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
}
