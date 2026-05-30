//! Built-in language adapters: TypeScript, Java, Python, Rust, and the generic `.jitgen.yaml`
//! adapter. Each owns a set of files (by extension/config), maps changes to targets via tree-sitter
//! symbol extraction, and derives an argv test command.

use crate::glob::glob_match;
use crate::lang::Lang;
use crate::snapshot::RepoSnapshot;
use crate::spi::{AdapterContext, DetectionResult, LanguageAdapter, TestCommand};
use crate::symbols::extract_targets;
use jitgen_core::{AdapterId, ChangeKind, ChangeSet, RepoConfig, Target};

/// Built-in adapter ids a generic `.jitgen.yaml` adapter may not claim (avoids dispatch collisions).
const RESERVED_BUILTIN_IDS: &[&str] = &["rust", "python", "java", "typescript"];

/// Shared change-analysis: for each non-deleted changed file this adapter owns, extract targets.
fn analyze_owned(
    owns: impl Fn(&str) -> Option<Lang>,
    adapter_id: &AdapterId,
    ctx: &AdapterContext,
    changes: &ChangeSet,
) -> Vec<Target> {
    let mut seq = 0u32;
    let mut out = Vec::new();
    for fc in &changes.files {
        if matches!(fc.kind, ChangeKind::Deleted) {
            continue; // no head content to extract symbols from
        }
        if let Some(lang) = owns(&fc.path) {
            let source = ctx.repo.read(&fc.path).unwrap_or(&[]);
            out.extend(extract_targets(
                Some(lang),
                source,
                &fc.path,
                adapter_id,
                &fc.hunks,
                &mut seq,
            ));
        }
    }
    out
}

// ---- Rust --------------------------------------------------------------------------------------

/// Rust (Cargo) adapter.
pub struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn id(&self) -> AdapterId {
        AdapterId::new("rust")
    }
    fn detect(&self, repo: &RepoSnapshot) -> DetectionResult {
        let mut ev = Vec::new();
        if repo.has("Cargo.toml") {
            ev.push("Cargo.toml".into());
        }
        if repo.has_ext("rs") {
            ev.push("*.rs sources".into());
        }
        if ev.is_empty() {
            DetectionResult::no()
        } else {
            DetectionResult::yes(ev)
        }
    }
    fn analyze_changes(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target> {
        analyze_owned(
            |p| (Lang::from_path(p) == Some(Lang::Rust)).then_some(Lang::Rust),
            &self.id(),
            ctx,
            changes,
        )
    }
    fn test_command(&self, _ctx: &AdapterContext, target: &Target) -> Option<TestCommand> {
        (target.adapter == self.id())
            .then(|| TestCommand::argv("cargo", ["test".into(), "--quiet".into()]))
    }
}

// ---- Python ------------------------------------------------------------------------------------

/// Python (pytest) adapter.
pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn id(&self) -> AdapterId {
        AdapterId::new("python")
    }
    fn detect(&self, repo: &RepoSnapshot) -> DetectionResult {
        let markers = [
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "pytest.ini",
            "tox.ini",
        ];
        let mut ev: Vec<String> = markers
            .iter()
            .filter(|m| repo.has(m))
            .map(|m| (*m).to_string())
            .collect();
        if repo.has_ext("py") {
            ev.push("*.py sources".into());
        }
        if ev.is_empty() {
            DetectionResult::no()
        } else {
            DetectionResult::yes(ev)
        }
    }
    fn analyze_changes(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target> {
        analyze_owned(
            |p| (Lang::from_path(p) == Some(Lang::Python)).then_some(Lang::Python),
            &self.id(),
            ctx,
            changes,
        )
    }
    fn test_command(&self, _ctx: &AdapterContext, target: &Target) -> Option<TestCommand> {
        (target.adapter == self.id())
            .then(|| TestCommand::argv("python3", ["-m".into(), "pytest".into(), "-q".into()]))
    }
}

// ---- Java --------------------------------------------------------------------------------------

/// Java (Maven/Gradle, JUnit) adapter.
pub struct JavaAdapter;

impl JavaAdapter {
    fn uses_maven(repo: &RepoSnapshot) -> bool {
        repo.has("pom.xml")
    }
    fn uses_gradle(repo: &RepoSnapshot) -> bool {
        repo.has("build.gradle") || repo.has("build.gradle.kts")
    }
}

impl LanguageAdapter for JavaAdapter {
    fn id(&self) -> AdapterId {
        AdapterId::new("java")
    }
    fn detect(&self, repo: &RepoSnapshot) -> DetectionResult {
        let mut ev = Vec::new();
        if Self::uses_maven(repo) {
            ev.push("pom.xml".into());
        }
        if Self::uses_gradle(repo) {
            ev.push("build.gradle".into());
        }
        if repo.has_ext("java") {
            ev.push("*.java sources".into());
        }
        if ev.is_empty() {
            DetectionResult::no()
        } else {
            DetectionResult::yes(ev)
        }
    }
    fn analyze_changes(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target> {
        analyze_owned(
            |p| (Lang::from_path(p) == Some(Lang::Java)).then_some(Lang::Java),
            &self.id(),
            ctx,
            changes,
        )
    }
    fn test_command(&self, ctx: &AdapterContext, target: &Target) -> Option<TestCommand> {
        if target.adapter != self.id() {
            return None;
        }
        if Self::uses_gradle(ctx.repo) && !Self::uses_maven(ctx.repo) {
            // Prefer the project wrapper (pinned toolchain) when present (F4/T1 review #6).
            let prog = if ctx.repo.has("gradlew") {
                "./gradlew"
            } else {
                "gradle"
            };
            Some(TestCommand::argv(prog, ["test".into()]))
        } else {
            // Maven (default when both/neither marker is present).
            let prog = if ctx.repo.has("mvnw") {
                "./mvnw"
            } else {
                "mvn"
            };
            Some(TestCommand::argv(prog, ["-q".into(), "test".into()]))
        }
    }
}

// ---- TypeScript / JavaScript -------------------------------------------------------------------

/// TypeScript/JavaScript (Jest/Vitest via npm/pnpm/yarn/bun) adapter.
pub struct TypeScriptAdapter;

impl TypeScriptAdapter {
    fn package_manager(repo: &RepoSnapshot) -> &'static str {
        if repo.has("pnpm-lock.yaml") {
            "pnpm"
        } else if repo.has("yarn.lock") {
            "yarn"
        } else if repo.has("bun.lockb") || repo.has("bun.lock") {
            "bun"
        } else {
            "npm"
        }
    }
}

impl LanguageAdapter for TypeScriptAdapter {
    fn id(&self) -> AdapterId {
        AdapterId::new("typescript")
    }
    fn detect(&self, repo: &RepoSnapshot) -> DetectionResult {
        let mut ev = Vec::new();
        if repo.has("package.json") {
            ev.push("package.json".into());
        }
        if repo.has("tsconfig.json") {
            ev.push("tsconfig.json".into());
        }
        if ["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"]
            .iter()
            .any(|e| repo.has_ext(e))
        {
            ev.push("JS/TS sources".into());
        }
        if ev.is_empty() {
            DetectionResult::no()
        } else {
            DetectionResult::yes(ev)
        }
    }
    fn analyze_changes(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target> {
        analyze_owned(
            |p| match Lang::from_path(p) {
                Some(Lang::TypeScript) => Some(Lang::TypeScript),
                Some(Lang::Tsx) => Some(Lang::Tsx),
                _ => None,
            },
            &self.id(),
            ctx,
            changes,
        )
    }
    fn test_command(&self, ctx: &AdapterContext, target: &Target) -> Option<TestCommand> {
        if target.adapter != self.id() {
            return None;
        }
        // Run the package's `test` script via the detected package manager (runner-specific targeted
        // invocation is refined during F9 e2e).
        let pm = Self::package_manager(ctx.repo);
        Some(match pm {
            "bun" => TestCommand::argv("bun", ["run".into(), "test".into()]),
            other => TestCommand::argv(other, ["test".into()]),
        })
    }
}

// ---- Generic (.jitgen.yaml) --------------------------------------------------------------------

/// Generic adapter driven by an (untrusted) repo `.jitgen.yaml` (extensions + argv template + an
/// allowlisted grammar). Holds the parsed [`RepoConfig`].
pub struct GenericAdapter {
    config: RepoConfig,
}

impl GenericAdapter {
    /// Build from the resolved repo config.
    pub fn new(config: RepoConfig) -> Self {
        Self { config }
    }

    fn adapter_id(&self) -> AdapterId {
        let raw = self
            .config
            .id
            .clone()
            .unwrap_or_else(|| "generic".to_string());
        // A repo `.jitgen.yaml` must not claim a built-in id (would misdispatch) — namespace it
        // under `generic-` if it tries (F4/T1 review #1).
        let id = if RESERVED_BUILTIN_IDS.contains(&raw.as_str()) {
            format!("generic-{raw}")
        } else {
            raw
        };
        AdapterId::new(id)
    }

    /// Whether `path` matches the configured extensions AND passes include/exclude globs
    /// (exclude wins; include, if present, is required) — F4/T1 review #5.
    fn owns(&self, path: &str) -> bool {
        let ext = path.rsplit('.').next().unwrap_or("");
        if !self.config.extensions.iter().any(|e| e == ext) {
            return false;
        }
        if self.config.exclude.iter().any(|g| glob_match(g, path)) {
            return false;
        }
        if !self.config.include.is_empty()
            && !self.config.include.iter().any(|g| glob_match(g, path))
        {
            return false;
        }
        true
    }

    /// Map the configured (allowlisted) grammar name to a `Lang`, if any.
    fn grammar_lang(&self) -> Option<Lang> {
        match self.config.grammar.as_deref() {
            Some("rust") => Some(Lang::Rust),
            Some("python") => Some(Lang::Python),
            Some("java") => Some(Lang::Java),
            Some("typescript") | Some("javascript") => Some(Lang::TypeScript),
            Some("tsx") => Some(Lang::Tsx),
            _ => None,
        }
    }
}

impl LanguageAdapter for GenericAdapter {
    fn id(&self) -> AdapterId {
        self.adapter_id()
    }
    fn detect(&self, _repo: &RepoSnapshot) -> DetectionResult {
        // Configured when the repo `.jitgen.yaml` declares an id and at least extensions or argv.
        let configured = self.config.id.is_some()
            && (!self.config.extensions.is_empty() || !self.config.test_argv.is_empty());
        if configured {
            DetectionResult::yes([".jitgen.yaml generic adapter".to_string()])
        } else {
            DetectionResult::no()
        }
    }
    fn analyze_changes(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target> {
        let id = self.adapter_id();
        let lang = self.grammar_lang();
        let mut seq = 0u32;
        let mut out = Vec::new();
        for fc in &changes.files {
            if matches!(fc.kind, ChangeKind::Deleted) || !self.owns(&fc.path) {
                continue;
            }
            let source = ctx.repo.read(&fc.path).unwrap_or(&[]);
            out.extend(extract_targets(
                lang, source, &fc.path, &id, &fc.hunks, &mut seq,
            ));
        }
        out
    }
    fn test_command(&self, _ctx: &AdapterContext, target: &Target) -> Option<TestCommand> {
        if target.adapter != self.adapter_id() || self.config.test_argv.is_empty() {
            return None;
        }
        // Substitute {target} as a whole argv element (never re-split — security §5).
        let argv = self.config.render_argv(&[("target", target.path.as_str())]);
        let (program, args) = argv.split_first()?;
        Some(TestCommand::argv(program.clone(), args.to_vec()))
    }
}
