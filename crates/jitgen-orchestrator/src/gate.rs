//! The findings **gate** (E4): turn a catch-mode [`RunReport`] into a CI exit decision.
//!
//! `jitgen run` exits 0 on any successful run by default, so it cannot fail a CI pipeline on a
//! surfaced bug. The gate adds an *opt-in*, *guarded* signal: with `--fail-on-catch` the run exits
//! non-zero when it surfaced a **high-confidence** catch.
//!
//! It is deliberately guarded, not a plain "any catch fails". Catch classification is
//! model-assessed ([`CatchDecision`] + [`tp_probability`](CatchReport::tp_probability)) and therefore
//! *nondeterministic* with a real provider, so a naive gate would flake builds run-to-run (design doc
//! "Architecture Issue 1"). The guards are: only [`CatchDecision::StrongCatch`] gates (a `StrictlyWeak`
//! test defect or an `Uncertain` verdict never does); the probability must clear a threshold; and a
//! catch listed in a [`Baseline`] is suppressed. The baseline keys on the catch's **stable identity**
//! (target + mutated path) — never the generated-test source, which a nondeterministic provider
//! rewrites each run, which would make suppression useless.
//!
//! The function here is pure (no I/O, no process exit): the CLI renders the report artifact, calls
//! [`gate_exit_code`], and maps the [`GateVerdict`] to a process exit code last — so the artifact is
//! always emitted, even when the gate trips (CI can still upload the SARIF).

use std::collections::HashSet;
use std::path::Path;

use jitgen_core::CatchDecision;
use jitgen_report::{CatchReport, RunReport};

/// Default minimum true-positive probability a [`StrongCatch`](CatchDecision::StrongCatch) must reach
/// to trip the gate. High by design: the gate should fire only on catches the assessor is confident
/// about, to keep a real-provider CI gate from flaking on borderline verdicts.
pub const DEFAULT_FAIL_THRESHOLD: f64 = 0.9;

/// Largest `--baseline` file jitgen will read. A baseline is a short list of fingerprints, not a data
/// file; the cap bounds memory/parse work on a malformed or hostile input (defensive — the path is an
/// operator-supplied CLI arg, but parse everything at a boundary as untrusted).
const MAX_BASELINE_BYTES: u64 = 1 << 20; // 1 MiB
/// Largest number of fingerprint entries accepted from a baseline (matches the codebase's 50k file
/// cap for familiarity; far above any real suppression list).
const MAX_BASELINE_ENTRIES: usize = 50_000;
/// Largest single line (bytes) accepted from a baseline. A fingerprint is `target [path]`; no real
/// one approaches this.
const MAX_BASELINE_LINE: usize = 4096;

/// What the findings gate decided. The CLI maps this to a process exit code and an optional one-line
/// stderr summary; the report artifact is always emitted *before* this is acted on.
#[derive(Debug, Clone, PartialEq)]
pub enum GateVerdict {
    /// The gate was not requested (`--fail-on-catch` absent) — exit 0. The default, unchanged behavior.
    Disabled,
    /// The gate ran and nothing qualified to gate — exit 0.
    Pass,
    /// The gate ran and ≥1 catch qualified, but `--warn-only` made it advisory — exit 0, findings
    /// surfaced for the operator/CI to see.
    Advisory(Vec<GatingFinding>),
    /// The gate ran and ≥1 catch qualified — the CLI exits non-zero (code 3).
    Triggered(Vec<GatingFinding>),
}

impl GateVerdict {
    /// Whether the CLI should exit non-zero for findings (only [`Triggered`](GateVerdict::Triggered)).
    pub fn is_failure(&self) -> bool {
        matches!(self, GateVerdict::Triggered(_))
    }

    /// The catches that qualified to gate (for `Advisory`/`Triggered`); empty otherwise.
    pub fn findings(&self) -> &[GatingFinding] {
        match self {
            GateVerdict::Advisory(f) | GateVerdict::Triggered(f) => f,
            GateVerdict::Disabled | GateVerdict::Pass => &[],
        }
    }
}

/// A single catch that met every gate condition: a [`StrongCatch`](CatchDecision::StrongCatch) at or
/// above the threshold that the baseline does not suppress. Carries the (already-redacted) identity so
/// the CLI can print a concise summary — the CLI still routes these strings through its terminal-safe
/// sink on the way out, since a redacted report value can still embed a hostile path/ref.
#[derive(Debug, Clone, PartialEq)]
pub struct GatingFinding {
    /// Target id (e.g. `t3`).
    pub target: String,
    /// The mutant's modified repo-relative path, if the catch carried a mutant.
    pub path: Option<String>,
    /// The combined true-positive probability that cleared the threshold.
    pub tp_probability: f64,
    /// The stable [`catch_fingerprint`] — copy this verbatim into a `--baseline` file to suppress it.
    pub fingerprint: String,
}

impl GatingFinding {
    fn from_catch(catch: &CatchReport) -> Self {
        Self {
            target: catch.target.clone(),
            path: catch
                .mutant
                .as_ref()
                .map(|m| m.path.clone())
                .filter(|p| !p.is_empty()),
            tp_probability: catch.tp_probability,
            fingerprint: catch_fingerprint(catch),
        }
    }
}

/// The stable identity of a catch for `--baseline` suppression: the catch's **target** plus the
/// mutant's **modified path** (both stable run-to-run), and deliberately **not** the generated-test
/// source, which a nondeterministic provider rewrites each run — source-keyed suppression would never
/// match twice. A catch without a mutant is keyed by its target alone.
///
/// The result is a single line with no surrounding whitespace, so it round-trips through a baseline
/// file (one fingerprint per line) by exact string match.
pub fn catch_fingerprint(catch: &CatchReport) -> String {
    match catch
        .mutant
        .as_ref()
        .map(|m| m.path.as_str())
        .filter(|p| !p.is_empty())
    {
        Some(path) => format!("{} {}", catch.target, path),
        None => catch.target.clone(),
    }
}

/// Compute the gate [`GateVerdict`] for a finished run. **Pure**: no I/O, no exit.
///
/// - `fail_on_catch` off → [`Disabled`](GateVerdict::Disabled) (the default; exit 0, unchanged).
/// - otherwise, collect every catch that is a [`StrongCatch`](CatchDecision::StrongCatch) **and** has
///   `tp_probability >= threshold` **and** is not in `baseline`. A `StrictlyWeak`/`Uncertain` verdict,
///   a below-threshold strong catch, and a baselined catch never qualify.
/// - none qualify → [`Pass`](GateVerdict::Pass) (exit 0). Harden runs carry no catches, so they are
///   always `Pass` here.
/// - some qualify → [`Advisory`](GateVerdict::Advisory) when `warn_only` (exit 0, surfaced), else
///   [`Triggered`](GateVerdict::Triggered) (the CLI exits non-zero).
pub fn gate_exit_code(
    report: &RunReport,
    threshold: f64,
    baseline: &Baseline,
    warn_only: bool,
    fail_on_catch: bool,
) -> GateVerdict {
    if !fail_on_catch {
        return GateVerdict::Disabled;
    }
    let gating: Vec<GatingFinding> = report
        .catches
        .iter()
        // A NaN tp_probability (only possible from a hand-tampered report) fails `>=` and so never
        // gates — fail-safe by construction.
        .filter(|c| {
            c.decision == CatchDecision::StrongCatch
                && c.tp_probability >= threshold
                && !baseline.contains(c)
        })
        .map(GatingFinding::from_catch)
        .collect();
    if gating.is_empty() {
        GateVerdict::Pass
    } else if warn_only {
        GateVerdict::Advisory(gating)
    } else {
        GateVerdict::Triggered(gating)
    }
}

/// A parsed catch baseline: the set of [`catch_fingerprint`]s to suppress from the gate (E4).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Baseline {
    entries: HashSet<String>,
}

impl Baseline {
    /// An empty baseline (suppresses nothing). Used when `--baseline` is absent.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether this baseline suppresses `catch` (by its [`catch_fingerprint`]).
    pub fn contains(&self, catch: &CatchReport) -> bool {
        self.entries.contains(&catch_fingerprint(catch))
    }

    /// Number of suppression entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the baseline has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Load a baseline from a file: one fingerprint per line, `#` comments and blank lines ignored.
    ///
    /// **Defensive** (the file is parsed as untrusted boundary input): the read is byte-capped
    /// ([`MAX_BASELINE_BYTES`]) so a huge file can't exhaust memory; non-UTF-8, control characters,
    /// over-long lines, and too many entries are rejected as [`GateError::Malformed`]. On a missing or
    /// unreadable file it returns [`GateError::Unreadable`]. Offending bytes are never echoed into the
    /// error (only a line number), so a hostile file can't inject terminal controls through an error.
    pub fn from_file(path: &Path) -> Result<Self, GateError> {
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|e| GateError::unreadable(path, e))?;
        // Read at most cap+1 bytes: if we get cap+1, the file is over the cap. Bounds memory without a
        // separate metadata() call (no TOCTOU window between size check and read).
        let mut buf = Vec::new();
        file.take(MAX_BASELINE_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| GateError::unreadable(path, e))?;
        if buf.len() as u64 > MAX_BASELINE_BYTES {
            return Err(GateError::TooLarge {
                path: path.display().to_string(),
                cap: MAX_BASELINE_BYTES,
            });
        }
        let text = std::str::from_utf8(&buf)
            .map_err(|_| malformed(Some(path), "file is not valid UTF-8 text".to_string()))?;
        Self::parse_inner(Some(path), text)
    }

    /// Parse a baseline from in-memory text (the I/O-free core of [`from_file`]).
    fn parse_inner(path: Option<&Path>, text: &str) -> Result<Self, GateError> {
        let mut entries = HashSet::new();
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            if raw.len() > MAX_BASELINE_LINE {
                return Err(malformed(
                    path,
                    format!("line {line_no} exceeds the {MAX_BASELINE_LINE}-byte line cap"),
                ));
            }
            let entry = raw.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue; // blank line or comment
            }
            // A fingerprint is printable text. A control char (incl. a stray CR or tab) can't belong to
            // a real fingerprint and would be a terminal-injection vector if ever echoed — reject the
            // line structurally, without echoing its bytes.
            if entry.chars().any(char::is_control) {
                return Err(malformed(
                    path,
                    format!("line {line_no} contains a control character"),
                ));
            }
            if entries.len() >= MAX_BASELINE_ENTRIES {
                return Err(malformed(
                    path,
                    format!("too many entries (cap {MAX_BASELINE_ENTRIES})"),
                ));
            }
            entries.insert(entry.to_string());
        }
        Ok(Self { entries })
    }
}

/// Build a [`GateError::Malformed`], appending the file path (operator-supplied) when known. Never
/// embeds untrusted file *content* — only structural facts (line number, what rule failed).
fn malformed(path: Option<&Path>, what: String) -> GateError {
    GateError::Malformed {
        detail: match path {
            Some(p) => format!("{what} (in {})", p.display()),
            None => what,
        },
    }
}

/// A typed `--baseline` load error. Every `Display` contains the phrase **"baseline file"**, the
/// stable anchor the CLI hint maps on.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// The baseline file could not be opened or read.
    #[error("baseline file is unreadable: {path} ({source})")]
    Unreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The baseline file exceeds the size cap (it is a fingerprint list, not a data file).
    #[error("baseline file is too large: it exceeds the {cap}-byte cap ({path})")]
    TooLarge { path: String, cap: u64 },
    /// The baseline file has a line jitgen will not accept (non-UTF-8, a control char, an over-long
    /// line, or too many entries). The offending bytes are never echoed — only a line number.
    #[error("baseline file is malformed: {detail}")]
    Malformed { detail: String },
}

impl GateError {
    fn unreadable(path: &Path, source: std::io::Error) -> Self {
        GateError::Unreadable {
            path: path.display().to_string(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{CatchClass, Mode, Strategy, TpBucket};
    use jitgen_report::{MutantInfo, RunSummary, REPORT_SCHEMA_VERSION};

    /// A synthetic catch (the offline mock yields no catches, so the gate is unit-tested with
    /// hand-built reports).
    fn mk_catch(
        target: &str,
        mutant_path: Option<&str>,
        decision: CatchDecision,
        p: f64,
    ) -> CatchReport {
        CatchReport {
            target: target.into(),
            language: "rust".into(),
            path: "tests/jitgen_x.rs".into(),
            source: "#[test] fn t() {}".into(),
            class: CatchClass::WeakCatch,
            decision,
            tp_probability: p,
            bucket: TpBucket::from_probability(p),
            rationale: "r".into(),
            mutant: mutant_path.map(|pp| MutantInfo {
                id: "m".into(),
                risk_description: "rd".into(),
                path: pp.into(),
            }),
            changed_path: None,
            changed_line: None,
            reproduction: "cargo test".into(),
            evidence: None,
        }
    }

    fn report(mode: Mode, catches: Vec<CatchReport>) -> RunReport {
        RunReport {
            schema_version: REPORT_SCHEMA_VERSION,
            jitgen_version: "0.0.0-test".into(),
            run_id: "run-1".into(),
            repo: "/r".into(),
            base: "base".into(),
            head: "head".into(),
            mode,
            strategy: Strategy::IntentAware,
            summary: RunSummary {
                catches: catches.len(),
                ..RunSummary::default()
            },
            accepted: vec![],
            catches,
            rejected: vec![],
            warnings: vec![],
        }
    }

    fn strong(p: f64) -> RunReport {
        report(
            Mode::Catch,
            vec![mk_catch(
                "t0",
                Some("src/a.rs"),
                CatchDecision::StrongCatch,
                p,
            )],
        )
    }

    // ---- gate_exit_code: the full decision matrix ----

    #[test]
    fn gate_off_is_disabled_even_with_a_qualifying_catch() {
        let v = gate_exit_code(
            &strong(0.99),
            DEFAULT_FAIL_THRESHOLD,
            &Baseline::empty(),
            false,
            false,
        );
        assert_eq!(v, GateVerdict::Disabled);
        assert!(!v.is_failure());
    }

    #[test]
    fn warn_only_surfaces_but_never_fails() {
        let v = gate_exit_code(
            &strong(0.99),
            DEFAULT_FAIL_THRESHOLD,
            &Baseline::empty(),
            true,
            true,
        );
        assert!(matches!(v, GateVerdict::Advisory(ref f) if f.len() == 1));
        assert!(!v.is_failure(), "warn-only must exit 0");
    }

    #[test]
    fn strong_catch_at_or_above_threshold_triggers() {
        // Above threshold.
        let above = gate_exit_code(&strong(0.95), 0.9, &Baseline::empty(), false, true);
        assert!(matches!(above, GateVerdict::Triggered(ref f) if f.len() == 1));
        assert!(above.is_failure());
        // Exactly at threshold — `>=` includes equality.
        let at = gate_exit_code(&strong(0.9), 0.9, &Baseline::empty(), false, true);
        assert!(at.is_failure(), "p == threshold must gate (>=)");
    }

    #[test]
    fn strong_catch_below_threshold_passes() {
        let v = gate_exit_code(&strong(0.89), 0.9, &Baseline::empty(), false, true);
        assert_eq!(v, GateVerdict::Pass);
    }

    #[test]
    fn strictly_weak_and_uncertain_never_gate_regardless_of_probability() {
        for decision in [CatchDecision::StrictlyWeak, CatchDecision::Uncertain] {
            // tp_probability 1.0 — maximal — still must not gate: only StrongCatch can.
            let r = report(
                Mode::Catch,
                vec![mk_catch("t0", Some("src/a.rs"), decision, 1.0)],
            );
            let v = gate_exit_code(&r, 0.9, &Baseline::empty(), false, true);
            assert_eq!(v, GateVerdict::Pass, "{decision:?} must never gate");
        }
    }

    #[test]
    fn baselined_strong_catch_passes() {
        let r = strong(0.99);
        let baseline = Baseline::parse_inner(None, "t0 src/a.rs").unwrap();
        let v = gate_exit_code(&r, 0.9, &baseline, false, true);
        assert_eq!(v, GateVerdict::Pass, "a baselined catch must be suppressed");
    }

    #[test]
    fn gates_if_any_of_several_catches_qualifies() {
        let r = report(
            Mode::Catch,
            vec![
                mk_catch("t0", Some("src/a.rs"), CatchDecision::StrongCatch, 0.5), // below threshold
                mk_catch("t1", Some("src/b.rs"), CatchDecision::StrictlyWeak, 1.0), // wrong decision
                mk_catch("t2", Some("src/c.rs"), CatchDecision::Uncertain, 1.0), // wrong decision
                mk_catch("t3", Some("src/d.rs"), CatchDecision::StrongCatch, 0.95), // QUALIFIES
            ],
        );
        let v = gate_exit_code(&r, 0.9, &Baseline::empty(), false, true);
        match v {
            GateVerdict::Triggered(f) => {
                assert_eq!(f.len(), 1, "only the one qualifying catch gates");
                assert_eq!(f[0].target, "t3");
                assert_eq!(f[0].path.as_deref(), Some("src/d.rs"));
                assert_eq!(f[0].fingerprint, "t3 src/d.rs");
            }
            other => panic!("expected Triggered, got {other:?}"),
        }
    }

    #[test]
    fn harden_run_with_no_catches_passes() {
        // Harden mode never carries catches; the gate is a no-op even when armed.
        let v = gate_exit_code(
            &report(Mode::Harden, vec![]),
            0.9,
            &Baseline::empty(),
            false,
            true,
        );
        assert_eq!(v, GateVerdict::Pass);
    }

    // ---- fingerprint stability ----

    #[test]
    fn fingerprint_keys_on_target_and_path_not_source() {
        let a = mk_catch("t3", Some("src/auth.rs"), CatchDecision::StrongCatch, 0.9);
        let mut b = a.clone();
        // A real provider rewrites the generated test source run-to-run; the fingerprint must not move.
        b.source = "totally different generated test body".into();
        assert_eq!(catch_fingerprint(&a), catch_fingerprint(&b));
        assert_eq!(catch_fingerprint(&a), "t3 src/auth.rs");
    }

    #[test]
    fn fingerprint_without_mutant_is_the_target_alone() {
        let c = mk_catch("t7", None, CatchDecision::StrongCatch, 0.9);
        assert_eq!(catch_fingerprint(&c), "t7");
    }

    // ---- baseline parsing (defensive) ----

    #[test]
    fn baseline_parse_accepts_comments_blanks_and_entries() {
        let b = Baseline::parse_inner(
            None,
            "# a comment\n\n  t0 src/a.rs  \nt1 src/b.rs\n# trailing comment\n",
        )
        .unwrap();
        assert_eq!(b.len(), 2);
        // Surrounding whitespace is trimmed, so the entry matches a fingerprint exactly.
        let c0 = mk_catch("t0", Some("src/a.rs"), CatchDecision::StrongCatch, 0.9);
        assert!(b.contains(&c0));
        // A different identity is not suppressed.
        let c2 = mk_catch("t2", Some("src/z.rs"), CatchDecision::StrongCatch, 0.9);
        assert!(!b.contains(&c2));
    }

    #[test]
    fn baseline_parse_rejects_control_characters_as_malformed() {
        let err = Baseline::parse_inner(None, "t0 src/a.rs\nt1\u{7}evil").unwrap_err();
        assert!(matches!(err, GateError::Malformed { .. }));
        // The error names the line, never echoes the bytes.
        let msg = err.to_string();
        assert!(msg.contains("baseline file is malformed"), "{msg}");
        assert!(msg.contains("line 2"), "{msg}");
        assert!(!msg.contains('\u{7}'), "bytes must not be echoed: {msg:?}");
    }

    #[test]
    fn baseline_parse_rejects_too_many_entries() {
        let huge: String = (0..=MAX_BASELINE_ENTRIES)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = Baseline::parse_inner(None, &huge).unwrap_err();
        assert!(matches!(err, GateError::Malformed { .. }));
        assert!(err.to_string().contains("too many entries"));
    }

    #[test]
    fn baseline_parse_rejects_an_over_long_line() {
        let line = "t0 ".to_string() + &"a".repeat(MAX_BASELINE_LINE);
        let err = Baseline::parse_inner(None, &line).unwrap_err();
        assert!(matches!(err, GateError::Malformed { .. }));
        assert!(err.to_string().contains("line cap"));
    }

    // ---- baseline file I/O (missing / too-large / round-trip) ----

    /// A unique temp path for a file-based test (no Date/rand available; use pid + an atomic counter).
    fn temp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("jitgen-gate-test-{}-{tag}-{n}", std::process::id()))
    }

    #[test]
    fn from_file_missing_file_is_typed_unreadable_error() {
        let err = Baseline::from_file(&temp_path("missing")).unwrap_err();
        assert!(matches!(err, GateError::Unreadable { .. }));
        assert!(err.to_string().contains("baseline file is unreadable"));
    }

    #[test]
    fn from_file_round_trips_and_suppresses() {
        let path = temp_path("roundtrip");
        std::fs::write(&path, "# known catch\nt0 src/a.rs\n").unwrap();
        let baseline = Baseline::from_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(baseline.len(), 1);
        assert!(baseline.contains(&mk_catch(
            "t0",
            Some("src/a.rs"),
            CatchDecision::StrongCatch,
            0.9
        )));
    }

    #[test]
    fn from_file_rejects_an_oversize_file() {
        let path = temp_path("toobig");
        // One byte over the cap.
        let blob = vec![b'a'; (MAX_BASELINE_BYTES + 1) as usize];
        std::fs::write(&path, &blob).unwrap();
        let err = Baseline::from_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, GateError::TooLarge { .. }));
        assert!(err.to_string().contains("baseline file is too large"));
    }

    #[test]
    fn from_file_propagates_malformed_with_path_context() {
        let path = temp_path("malformed");
        std::fs::write(&path, "t0 src/a.rs\nbad\u{1b}line\n").unwrap();
        let err = Baseline::from_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, GateError::Malformed { .. }));
        // Malformed-from-file carries the path for context, but never the offending byte.
        let msg = err.to_string();
        assert!(msg.contains("line 2"), "{msg}");
        assert!(!msg.contains('\u{1b}'), "ESC must not be echoed: {msg:?}");
    }
}
