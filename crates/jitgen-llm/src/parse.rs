//! Parse raw model output into a [`TestCandidate`].

use crate::util::char_prefix;
use jitgen_core::{TargetId, TestCandidate};

/// Hard cap on raw model output we will parse. The deterministic mock and a real provider's own
/// response cap keep output small, but this bounds work defensively if either is bypassed or a
/// future provider streams a very large body (F5/S1 #5).
const MAX_RAW_BYTES: usize = 256 * 1024;

/// Extract the body of the first fenced code block, else the trimmed raw text. **Line-aware**
/// (F5/T1 review #3): the opening fence is a line that (after indentation) starts with ```` ``` ````
/// plus an optional info string; the closing fence is a later line that starts with ```` ``` ````.
/// Inline backticks within a line never trigger a fence. Input is byte-capped first (F5/S1 #5).
pub fn extract_code(raw: &str) -> String {
    let raw = char_prefix(raw, MAX_RAW_BYTES);
    let lines: Vec<&str> = raw.lines().collect();
    let open = lines.iter().position(|l| l.trim_start().starts_with("```"));
    if let Some(start) = open {
        let close = lines[start + 1..]
            .iter()
            .position(|l| l.trim_start().starts_with("```"))
            .map(|rel| start + 1 + rel);
        let end = close.unwrap_or(lines.len());
        return lines[start + 1..end].join("\n").trim_end().to_string();
    }
    raw.trim().to_string()
}

/// Build a [`TestCandidate`] from raw output for a target, with the caller-chosen overlay rel path.
pub fn parse_candidate(
    raw: &str,
    target: &TargetId,
    rel_path: &str,
    attempt: u16,
) -> TestCandidate {
    TestCandidate {
        target: target.clone(),
        rel_path: rel_path.to_string(),
        source: extract_code(raw),
        test_name: None,
        attempt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_fenced_block_with_lang_tag() {
        let raw = "Here:\n\n```rust\n#[test]\nfn t() {}\n```\nthanks";
        assert_eq!(extract_code(raw), "#[test]\nfn t() {}");
    }

    #[test]
    fn extracts_fenced_block_without_lang_tag() {
        assert_eq!(extract_code("```\ncode line\n```"), "code line");
    }

    #[test]
    fn falls_back_to_raw_when_no_fence() {
        assert_eq!(extract_code("  bare code  "), "bare code");
    }

    #[test]
    fn inline_backticks_do_not_trigger_a_fence() {
        // The prose line has inline backticks but doesn't start with ```; the real block follows.
        let raw = "Use the `foo` helper:\n```rust\nfn t() { let x = `nope`; }\n```";
        assert_eq!(extract_code(raw), "fn t() { let x = `nope`; }");
    }

    #[test]
    fn builds_candidate() {
        let c = parse_candidate("```\nx\n```", &TargetId::new("t0"), "src/a.test.ts", 2);
        assert_eq!(c.source, "x");
        assert_eq!(c.rel_path, "src/a.test.ts");
        assert_eq!(c.attempt, 2);
    }
}
