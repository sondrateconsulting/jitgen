//! Markdown report (security.md §10).
//!
//! Static structure (headings, table scaffolding) is trusted; every interpolated value is routed
//! through [`crate::escape`]: inline fields via [`md_inline`] (cannot form headings/links/tables/HTML)
//! and embedded sources via [`md_code_block`] inside a `~~~` fence (which a backtick run cannot
//! close, and whose own `~~~` runs are neutralized).

use crate::escape::{md_code_block, md_inline, CAP_NAME, CAP_SOURCE, CAP_TEXT};
use crate::model::{CatchReport, RunReport};
use jitgen_core::{CatchDecision, Mode};

/// Render the Markdown document.
pub(crate) fn render(report: &RunReport) -> String {
    let mut s = String::new();
    s.push_str("# jitgen report\n\n");
    summary_section(&mut s, report);

    match report.mode {
        Mode::Harden => accepted_section(&mut s, report),
        Mode::Catch => catches_section(&mut s, report),
    }
    rejected_section(&mut s, report);
    warnings_section(&mut s, report);
    s
}

fn summary_section(s: &mut String, r: &RunReport) {
    s.push_str("## Summary\n\n");
    s.push_str("| Field | Value |\n|---|---|\n");
    row(s, "run id", &md_inline(&r.run_id, CAP_NAME));
    row(s, "repo", &md_inline(&r.repo, CAP_NAME));
    row(s, "base", &md_inline(&r.base, CAP_NAME));
    row(s, "head", &md_inline(&r.head, CAP_NAME));
    row(s, "mode", r.mode.as_str());
    row(s, "strategy", strategy_str(r));
    row(
        s,
        "targets selected",
        &r.summary.targets_selected.to_string(),
    );
    row(
        s,
        "candidates generated",
        &r.summary.candidates_generated.to_string(),
    );
    row(s, "accepted", &r.summary.accepted.to_string());
    row(s, "catches", &r.summary.catches.to_string());
    row(s, "rejected", &r.summary.rejected.to_string());
    s.push('\n');
}

fn strategy_str(r: &RunReport) -> &'static str {
    match r.strategy {
        jitgen_core::Strategy::Auto => "auto",
        jitgen_core::Strategy::Harden => "harden",
        jitgen_core::Strategy::DodgyDiff => "dodgy-diff",
        jitgen_core::Strategy::IntentAware => "intent-aware",
    }
}

fn row(s: &mut String, k: &str, v: &str) {
    s.push_str(&format!("| {k} | {v} |\n"));
}

fn accepted_section(s: &mut String, r: &RunReport) {
    s.push_str("## Accepted tests (landable)\n\n");
    if r.accepted.is_empty() {
        s.push_str("_No tests were accepted._\n\n");
        return;
    }
    for t in &r.accepted {
        s.push_str(&format!("### `{}`\n\n", md_inline(&t.path, CAP_NAME)));
        s.push_str(&format!(
            "- target: `{}`\n- language: `{}`\n",
            md_inline(&t.target, CAP_NAME),
            md_inline(&t.language, CAP_NAME),
        ));
        if let Some(sym) = &t.symbol {
            s.push_str(&format!("- symbol: `{}`\n", md_inline(sym, CAP_NAME)));
        }
        s.push_str(&format!(
            "- reproduction: {}\n\n",
            md_inline(&t.reproduction, CAP_TEXT)
        ));
        code_fence(s, &t.language, &t.source);
    }
}

fn catches_section(s: &mut String, r: &RunReport) {
    s.push_str("## Catches (report-only)\n\n");
    s.push_str(
        "_Catch mode reports potential bugs; catching tests fail by design and are never landed._\n\n",
    );
    if r.catches.is_empty() {
        s.push_str("_No catches found._\n\n");
        return;
    }
    for c in &r.catches {
        catch_entry(s, c);
    }
}

fn catch_entry(s: &mut String, c: &CatchReport) {
    let sev = crate::model::severity_of(c.decision, c.tp_probability);
    s.push_str(&format!(
        "### {} {} — `{}`\n\n",
        severity_marker(sev),
        decision_name(c.decision),
        md_inline(&c.path, CAP_NAME)
    ));
    s.push_str(&format!(
        "- target: `{}`\n- language: `{}`\n- decision: **{:?}**\n- tp_probability: {:.2} ({:?})\n",
        md_inline(&c.target, CAP_NAME),
        md_inline(&c.language, CAP_NAME),
        c.decision,
        c.tp_probability,
        c.bucket,
    ));
    if let Some(m) = &c.mutant {
        s.push_str(&format!(
            "- mutant `{}`: {} (`{}`)\n",
            md_inline(&m.id, CAP_NAME),
            md_inline(&m.risk_description, CAP_TEXT),
            md_inline(&m.path, CAP_NAME),
        ));
    }
    s.push_str(&format!(
        "- rationale: {}\n- reproduction: {}\n\n",
        md_inline(&c.rationale, CAP_TEXT),
        md_inline(&c.reproduction, CAP_TEXT),
    ));
    code_fence(s, &c.language, &c.source);
}

/// The severity icon, kept in sync with [`crate::model::severity_of`] so Markdown's marker always
/// matches the SARIF level (🔴 = `error`, 🟡 = `warning`, ⚪ = `note`).
fn severity_marker(sev: crate::model::Severity) -> &'static str {
    use crate::model::Severity;
    match sev {
        Severity::High => "🔴",
        Severity::Medium => "🟡",
        Severity::Low => "⚪",
    }
}

/// The decision's display name (its severity icon comes from [`severity_marker`]).
fn decision_name(d: CatchDecision) -> &'static str {
    match d {
        CatchDecision::StrongCatch => "Strong catch",
        CatchDecision::StrictlyWeak => "Strictly weak",
        CatchDecision::Uncertain => "Uncertain",
    }
}

fn rejected_section(s: &mut String, r: &RunReport) {
    if r.rejected.is_empty() {
        return;
    }
    s.push_str("## Rejected candidates\n\n");
    s.push_str("| Target | Path | Reason |\n|---|---|---|\n");
    for rej in &r.rejected {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            md_inline(&rej.target, CAP_NAME),
            md_inline(&rej.path, CAP_NAME),
            md_inline(&rej.reason, CAP_TEXT),
        ));
    }
    s.push('\n');
}

fn warnings_section(s: &mut String, r: &RunReport) {
    if r.warnings.is_empty() {
        return;
    }
    s.push_str("## Warnings\n\n");
    for w in &r.warnings {
        s.push_str(&format!("- {}\n", md_inline(w, CAP_TEXT)));
    }
    s.push('\n');
}

/// Emit a `~~~`-fenced code block with a sanitized info string and a fence-safe body.
fn code_fence(s: &mut String, language: &str, source: &str) {
    let lang = lang_slug(language);
    s.push_str("~~~");
    s.push_str(&lang);
    s.push('\n');
    s.push_str(&md_code_block(source, CAP_SOURCE));
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("~~~\n\n");
}

/// A short, safe fence info string: only `[A-Za-z0-9_+-]`, capped.
fn lang_slug(language: &str) -> String {
    language
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-'))
        .take(24)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AcceptedTest, MutantInfo, RejectedCandidate, RunSummary};
    use jitgen_core::{CatchClass, Strategy, TpBucket};

    fn base_report(mode: Mode) -> RunReport {
        RunReport {
            schema_version: 1,
            jitgen_version: "0.1.0".into(),
            run_id: "run-1".into(),
            repo: "/repo".into(),
            base: "base".into(),
            head: "head".into(),
            mode,
            strategy: Strategy::Harden,
            summary: RunSummary::default(),
            accepted: vec![],
            catches: vec![],
            rejected: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn harden_report_lists_accepted_with_fenced_source() {
        let mut r = base_report(Mode::Harden);
        r.accepted.push(AcceptedTest {
            target: "t0".into(),
            symbol: Some("add".into()),
            language: "rust".into(),
            path: "tests/jitgen_add.rs".into(),
            source: "#[test]\nfn t() {}\n".into(),
            class: CatchClass::HardenPass,
            reproduction: "cargo test".into(),
        });
        let md = render(&r);
        assert!(md.contains("# jitgen report"));
        assert!(md.contains("## Accepted tests"));
        assert!(md.contains("~~~rust"));
        assert!(md.contains("#[test]"));
    }

    #[test]
    fn catch_report_shows_decision_and_mutant() {
        let mut r = base_report(Mode::Catch);
        r.strategy = Strategy::IntentAware;
        r.catches.push(CatchReport {
            target: "t0".into(),
            language: "rust".into(),
            path: "tests/jitgen_c.rs".into(),
            source: "#[test] fn c() {}".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.92,
            bucket: TpBucket::VeryHigh,
            rationale: "clean assertion".into(),
            mutant: Some(MutantInfo {
                id: "m0".into(),
                risk_description: "off-by-one".into(),
                path: "src/a.rs".into(),
            }),
            changed_path: None,
            changed_line: None,
            reproduction: "cargo test --test jitgen_c".into(),
        });
        let md = render(&r);
        assert!(md.contains("## Catches"));
        assert!(md.contains("Strong catch"));
        assert!(md.contains("mutant `m0`"));
        assert!(md.contains("0.92"));
    }

    #[test]
    fn injection_in_test_name_is_neutralized() {
        // A hostile path attempting a heading + a link breakout must be escaped as data.
        let mut r = base_report(Mode::Harden);
        r.accepted.push(AcceptedTest {
            target: "t0".into(),
            symbol: None,
            language: "rust".into(),
            path: "# PWNED\n[x](http://evil)".into(),
            source: "ok();\n```\n# heading\n".into(),
            class: CatchClass::HardenPass,
            reproduction: "x".into(),
        });
        let md = render(&r);
        // No raw heading or link injected from the untrusted path.
        assert!(!md.contains("\n# PWNED"));
        assert!(!md.contains("[x](http://evil)"));
        // The fenced source cannot break out of the ~~~ fence with ```.
        let body_start = md.find("~~~rust").unwrap();
        let after = &md[body_start + 7..];
        let fence_close = after.find("\n~~~").unwrap();
        assert!(!after[..fence_close].contains("```"));
    }

    #[test]
    fn rejected_and_warnings_render_when_present() {
        let mut r = base_report(Mode::Harden);
        r.rejected.push(RejectedCandidate {
            target: "t1".into(),
            path: "tests/b.rs".into(),
            reason: "flaky".into(),
            class: Some(CatchClass::Flaky),
        });
        r.warnings.push("ignored key 'shell'".into());
        let md = render(&r);
        assert!(md.contains("## Rejected candidates"));
        assert!(md.contains("flaky"));
        assert!(md.contains("## Warnings"));
        assert!(md.contains("ignored key"));
    }
}
