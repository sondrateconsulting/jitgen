//! Helpers for the LLM-driven steps: build a request from a step [`Prompt`], and **defensively parse**
//! structured risk/mutant responses (count-capped, size-capped, redacted).
//!
//! All parsing is bounded so hostile/over-large model output cannot blow up work or memory, and every
//! human-readable field is `redact`ed before it can reach a report or a later prompt. A mutant's
//! `diff` is kept **faithful** (only size-capped) because the executor must apply it; output-time
//! redaction is the report layer's job (security.md §3/§10). Garbage input parses to **empty** (the
//! strategy then yields no candidates — a safe no-op), so the real `MockProvider` (which emits a test,
//! not risks/mutants) degrades gracefully.

use jitgen_context::redact;
use jitgen_core::{Mode, Mutant, MutantStatus, Strategy};
use jitgen_llm::LlmRequest;

/// Caps (DoS bounds; security.md §9).
const MAX_RAW_BYTES: usize = 256 * 1024;
const MAX_RISKS: usize = 24;
const MAX_RISK_CHARS: usize = 200;
const MAX_MUTANTS: usize = 16;
const MAX_MUTANT_DIFF_CHARS: usize = 8 * 1024;
const MAX_PATH_CHARS: usize = 512;

/// Build an [`LlmRequest`] for a step prompt. `symbol`/`language` route the deterministic mock and
/// label real-provider requests.
pub(crate) fn request(
    prompt: jitgen_context::Prompt,
    mode: Mode,
    strategy: Strategy,
    language: &str,
    symbol: Option<&str>,
) -> LlmRequest {
    LlmRequest {
        prompt,
        mode,
        strategy,
        language: language.to_string(),
        symbol: symbol.map(str::to_string),
        attempt: 0,
        repair_feedback: None,
    }
}

/// A char-prefix that never splits a UTF-8 boundary (bounds the work like the F5 parser).
fn char_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Collect the bodies of ALL fenced code blocks (line-aware, like `extract_code` but multi-block).
/// An unterminated final fence runs to EOF.
fn fenced_blocks(raw: &str) -> Vec<String> {
    let raw = char_prefix(raw, MAX_RAW_BYTES);
    let lines: Vec<&str> = raw.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("```") {
            let start = i + 1;
            let mut j = start;
            while j < lines.len() && !lines[j].trim_start().starts_with("```") {
                j += 1;
            }
            blocks.push(lines[start..j].join("\n").trim_end().to_string());
            i = j + 1; // skip the closing fence (or past EOF)
        } else {
            i += 1;
        }
    }
    blocks
}

/// Parse inferred risks from the **first fenced block**: one risk per non-empty line, redacted,
/// capped. A fence is REQUIRED (T1/F8 #4): unfenced prose is never treated as risks (so a chatty or
/// hostile non-structured response degrades to empty rather than smuggling lines through).
pub(crate) fn parse_risks(raw: &str) -> Vec<String> {
    let block = match fenced_blocks(raw).into_iter().next() {
        Some(b) => b,
        None => return Vec::new(),
    };
    block
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(MAX_RISKS)
        .map(|l| {
            let red = redact(l).text;
            red.chars().take(MAX_RISK_CHARS).collect::<String>()
        })
        .collect()
}

/// Parse mutants from fenced blocks. Each block's first line must be `path: <repo-relative path>`;
/// the remainder is the unified diff. Blocks without a `path:` header, or with an empty path/diff, are
/// skipped. Ids are `{id_prefix}-m{n}`.
pub(crate) fn parse_mutants(raw: &str, id_prefix: &str) -> Vec<Mutant> {
    let mut mutants = Vec::new();
    for block in fenced_blocks(raw).into_iter().take(MAX_MUTANTS) {
        let mut lines = block.lines();
        let header = match lines.next() {
            Some(h) => h.trim(),
            None => continue,
        };
        let path = match header
            .strip_prefix("path:")
            .or_else(|| header.strip_prefix("path ="))
        {
            Some(p) => p.trim(),
            None => continue,
        };
        if path.is_empty() {
            continue;
        }
        let diff: String = lines.collect::<Vec<_>>().join("\n");
        if diff.trim().is_empty() {
            continue;
        }
        let n = mutants.len();
        mutants.push(Mutant {
            id: format!("{id_prefix}-m{n}"),
            // The risk is filled by the caller (it owns the risk list); default to a stable label.
            risk_description: redact(&format!("mutant {n}")).text,
            path: path.chars().take(MAX_PATH_CHARS).collect(),
            diff: diff.chars().take(MAX_MUTANT_DIFF_CHARS).collect(),
            status: MutantStatus::Proposed,
        });
    }
    mutants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_risk_lines_and_caps_count() {
        let mut body = String::from("```\n");
        for i in 0..50 {
            body.push_str(&format!("risk {i}\n"));
        }
        body.push_str("```\n");
        let risks = parse_risks(&body);
        assert_eq!(risks.len(), MAX_RISKS);
        assert_eq!(risks[0], "risk 0");
    }

    #[test]
    fn risks_are_redacted() {
        let raw = "```\noff-by-one near ghp_0123456789abcdefghijABCDEFGHIJ012345\n```";
        let risks = parse_risks(raw);
        assert_eq!(risks.len(), 1);
        assert!(!risks[0].contains("ghp_0123456789"), "{:?}", risks);
    }

    #[test]
    fn garbage_parses_to_empty() {
        // Unfenced prose is NOT risks (a fence is required); empty input is empty.
        assert!(parse_risks("no fence, just prose").is_empty());
        assert!(parse_risks("").is_empty());
        assert!(parse_mutants("not a mutant block", "t1").is_empty());
    }

    #[test]
    fn risks_require_a_fence() {
        // A fenced block yields risks; the same lines unfenced yield nothing.
        assert_eq!(parse_risks("```\noff-by-one\nnull deref\n```").len(), 2);
        assert!(parse_risks("off-by-one\nnull deref").is_empty());
    }

    #[test]
    fn parses_multiple_mutants_with_path_header() {
        let raw = "Here are mutants:\n\
            ```\npath: src/a.rs\n@@ -1 +1 @@\n-<=\n+<\n```\n\
            ```\npath: src/b.rs\n@@ -2 +2 @@\n-x\n+y\n```\n";
        let mutants = parse_mutants(raw, "t1");
        assert_eq!(mutants.len(), 2);
        assert_eq!(mutants[0].id, "t1-m0");
        assert_eq!(mutants[0].path, "src/a.rs");
        assert!(mutants[0].diff.contains("@@ -1 +1 @@"));
        assert_eq!(mutants[1].path, "src/b.rs");
        assert_eq!(mutants[1].status, MutantStatus::Proposed);
    }

    #[test]
    fn mutant_block_without_path_header_is_skipped() {
        let raw = "```\n@@ -1 +1 @@\n-<=\n+<\n```";
        assert!(parse_mutants(raw, "t1").is_empty());
    }

    #[test]
    fn mutant_count_is_capped() {
        // 40 small blocks all fit under the raw byte cap, so the MAX_MUTANTS count cap is what bites.
        let mut raw = String::new();
        for i in 0..40 {
            raw.push_str(&format!(
                "```\npath: src/f{i}.rs\n@@ -1 +1 @@\n-a\n+b\n```\n"
            ));
        }
        let mutants = parse_mutants(&raw, "t1");
        assert_eq!(mutants.len(), MAX_MUTANTS);
    }

    #[test]
    fn mutant_diff_size_is_capped() {
        let raw = format!("```\npath: src/a.rs\n{}\n```\n", "x".repeat(20_000));
        let mutants = parse_mutants(&raw, "t1");
        assert_eq!(mutants.len(), 1);
        assert!(mutants[0].diff.len() <= MAX_MUTANT_DIFF_CHARS);
    }

    #[test]
    fn oversized_raw_is_byte_capped_before_parsing() {
        // A pathologically large response is truncated to the raw byte cap (DoS bound), so only a
        // bounded number of blocks are ever materialized regardless of how many were sent.
        let mut raw = String::new();
        for i in 0..40 {
            raw.push_str(&format!(
                "```\npath: src/f{i}.rs\n{}\n```\n",
                "x".repeat(20_000)
            ));
        }
        let mutants = parse_mutants(&raw, "t1");
        assert!(mutants.len() <= MAX_MUTANTS);
        assert!(mutants
            .iter()
            .all(|m| m.diff.len() <= MAX_MUTANT_DIFF_CHARS));
    }
}
