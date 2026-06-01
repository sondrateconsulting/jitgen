#![forbid(unsafe_code)]
//! `jitgen-report` — reporting & export. Pipeline layer 10 (`docs/architecture.md` §10,
//! `docs/security.md` §10).
//!
//! Emits a unified **patch** (default, harden mode), plus **JSON**, **Markdown**/human, and optional
//! **JUnit** and **SARIF**. The crate is intentionally light (depends only on `jitgen-core` +
//! `serde_json`): it owns the report **data contract** ([`RunReport`]) and the **renderers**.
//!
//! Security split (security.md §10): the *producer* (the orchestrator) redacts every string it places
//! into a [`RunReport`]; the *renderers* here additionally guarantee untrusted strings are rendered as
//! **data, never markup or terminal controls** — per-format escaping, ANSI/control stripping, and
//! length caps live in [`escape`].

mod escape;
mod exporters;
mod model;

pub use escape::{cap, md_inline, sanitize, strip_controls, xml_attr, xml_text};
pub use model::{
    AcceptedTest, CatchReport, MutantInfo, RejectedCandidate, RunReport, RunSummary,
    REPORT_SCHEMA_VERSION,
};

/// A render target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Human-readable terminal output (ANSI/control-stripped).
    Human,
    /// The canonical JSON artifact.
    Json,
    /// Markdown document.
    Markdown,
    /// Unified diff of landable tests (harden mode).
    Patch,
    /// JUnit XML.
    Junit,
    /// SARIF 2.1.0 JSON.
    Sarif,
}

impl ReportFormat {
    /// Parse a `--format` value. Returns `None` for an unknown format.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "human" => Some(ReportFormat::Human),
            "json" => Some(ReportFormat::Json),
            "markdown" | "md" => Some(ReportFormat::Markdown),
            "patch" | "diff" => Some(ReportFormat::Patch),
            "junit" => Some(ReportFormat::Junit),
            "sarif" => Some(ReportFormat::Sarif),
            _ => None,
        }
    }

    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            ReportFormat::Human => "human",
            ReportFormat::Json => "json",
            ReportFormat::Markdown => "markdown",
            ReportFormat::Patch => "patch",
            ReportFormat::Junit => "junit",
            ReportFormat::Sarif => "sarif",
        }
    }
}

/// Render `report` in `format`. JSON serialization is the only fallible path (and only on an internal
/// serializer error, which does not occur for a well-formed [`RunReport`]); it falls back to an error
/// comment so callers always get a string.
pub fn render(report: &RunReport, format: ReportFormat) -> String {
    match format {
        ReportFormat::Human => exporters::human::render(report),
        ReportFormat::Json => exporters::json::render(report),
        ReportFormat::Markdown => exporters::markdown::render(report),
        ReportFormat::Patch => exporters::patch::render(report),
        ReportFormat::Junit => exporters::junit::render(report),
        ReportFormat::Sarif => exporters::sarif::render(report),
    }
}

/// Stable identifier for this pipeline layer/crate.
pub fn layer_id() -> &'static str {
    "jitgen-report"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_roundtrips() {
        for f in [
            ReportFormat::Human,
            ReportFormat::Json,
            ReportFormat::Markdown,
            ReportFormat::Patch,
            ReportFormat::Junit,
            ReportFormat::Sarif,
        ] {
            assert_eq!(ReportFormat::parse(f.as_str()), Some(f));
        }
        assert_eq!(ReportFormat::parse("md"), Some(ReportFormat::Markdown));
        assert_eq!(ReportFormat::parse("bogus"), None);
    }

    #[test]
    fn layer_id_matches_crate_name() {
        assert_eq!(layer_id(), "jitgen-report");
    }

    #[test]
    fn links_against_core_contract() {
        assert!(!jitgen_core::version().is_empty());
    }
}
