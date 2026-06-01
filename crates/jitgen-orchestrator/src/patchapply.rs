//! A small, **fail-closed** unified-diff applier for mutants (ADR-0002 intent-aware pipeline).
//!
//! A `Mutant`'s `diff` is LLM-derived data. The executor applies it to a checked-out *base* overlay
//! to produce the "parent + mutation" variant — it is **never** shelled out (security.md §2/§5: LLM
//! output is never executed). This applier validates every context/removed line against the original
//! and **errors on any mismatch, malformed header, or truncation**, so a bad diff yields an
//! `Invalid`/`Broken` mutant rather than a corrupted file.

use crate::error::{OrchestratorError, Result};

/// Apply a unified `diff` to `original`, returning the patched text. Fails closed on any mismatch.
pub fn apply_unified_diff(original: &str, diff: &str) -> Result<String> {
    let orig_has_trailing_nl = original.ends_with('\n');
    let orig_lines: Vec<&str> = split_lines(original);

    let mut out: Vec<String> = Vec::new();
    let mut cursor = 0usize; // index into orig_lines
    let mut lines = diff.lines().peekable();

    while let Some(line) = lines.next() {
        if let Some(rest) = line.strip_prefix("@@") {
            let h = parse_hunk_header(rest)?;
            // `old_start == 0` is only valid for a pure insertion (no old lines); anything that
            // claims to touch old lines at line 0 is malformed.
            if h.old_start == 0 && h.old_count > 0 {
                return Err(malformed("old_start 0 with a non-empty old range"));
            }
            // Copy unchanged lines up to the hunk's old start (1-based).
            let target = h.old_start.saturating_sub(1);
            if target > orig_lines.len() {
                return Err(malformed("hunk start past end of file"));
            }
            // Hunks must be strictly forward-ordered: a target before the cursor means an
            // out-of-order or overlapping hunk — fail closed rather than silently misapplying it.
            if target < cursor {
                return Err(malformed("hunk out of order / overlapping a prior hunk"));
            }
            while cursor < target {
                out.push(orig_lines[cursor].to_string());
                cursor += 1;
            }
            apply_hunk(&h, &orig_lines, &mut cursor, &mut out, &mut lines)?;
        } else if is_file_header(line) || line.is_empty() {
            continue; // tolerate `diff --git`/`---`/`+++`/`index`/blank lines between hunks
        } else {
            return Err(malformed("unexpected content outside a hunk"));
        }
    }

    // Copy any trailing unchanged lines.
    while cursor < orig_lines.len() {
        out.push(orig_lines[cursor].to_string());
        cursor += 1;
    }

    let mut result = out.join("\n");
    if orig_has_trailing_nl && !result.is_empty() {
        result.push('\n');
    }
    Ok(result)
}

struct Hunk {
    old_start: usize,
    old_count: usize,
    new_count: usize,
}

/// Parse the part of an `@@ -old_start,old_count +new_start,new_count @@` header after the `@@`.
fn parse_hunk_header(rest: &str) -> Result<Hunk> {
    // rest looks like " -a,b +c,d @@ optional section heading"
    let inner = rest.trim_start();
    let mut parts = inner.split_whitespace();
    let old = parts
        .next()
        .and_then(|p| p.strip_prefix('-'))
        .ok_or_else(|| malformed("missing old range"))?;
    let new = parts
        .next()
        .and_then(|p| p.strip_prefix('+'))
        .ok_or_else(|| malformed("missing new range"))?;
    let (old_start, old_count) = parse_range(old)?;
    let (_new_start, new_count) = parse_range(new)?;
    Ok(Hunk {
        old_start,
        old_count,
        new_count,
    })
}

/// Parse `start` or `start,count` (count defaults to 1).
fn parse_range(s: &str) -> Result<(usize, usize)> {
    let mut it = s.split(',');
    let start = it
        .next()
        .and_then(|n| n.parse::<usize>().ok())
        .ok_or_else(|| malformed("bad range start"))?;
    let count = match it.next() {
        Some(c) => c
            .parse::<usize>()
            .map_err(|_| malformed("bad range count"))?,
        None => 1,
    };
    Ok((start, count))
}

/// Apply one hunk body, consuming exactly `old_count`/`new_count` affecting lines.
fn apply_hunk<'a, I>(
    h: &Hunk,
    orig: &[&str],
    cursor: &mut usize,
    out: &mut Vec<String>,
    lines: &mut std::iter::Peekable<I>,
) -> Result<()>
where
    I: Iterator<Item = &'a str>,
{
    let mut old_seen = 0usize;
    let mut new_seen = 0usize;
    while old_seen < h.old_count || new_seen < h.new_count {
        let body = lines.next().ok_or_else(|| malformed("hunk truncated"))?;
        // A bare empty line inside a hunk is an empty context line.
        let (op, content) = match body.chars().next() {
            None => (' ', ""),
            Some(c) => (c, &body[c.len_utf8()..]),
        };
        match op {
            ' ' => {
                expect_match(orig, *cursor, content)?;
                out.push(content.to_string());
                *cursor += 1;
                old_seen += 1;
                new_seen += 1;
            }
            '-' => {
                expect_match(orig, *cursor, content)?;
                *cursor += 1;
                old_seen += 1;
            }
            '+' => {
                out.push(content.to_string());
                new_seen += 1;
            }
            '\\' => { /* "\ No newline at end of file" — no content effect */ }
            _ => return Err(malformed("bad hunk body line")),
        }
    }
    Ok(())
}

fn expect_match(orig: &[&str], idx: usize, content: &str) -> Result<()> {
    if idx >= orig.len() || orig[idx] != content {
        return Err(malformed("context/removed line does not match original"));
    }
    Ok(())
}

/// Split into lines without a trailing empty element (mirrors how we rejoin with `\n`).
fn split_lines(s: &str) -> Vec<&str> {
    if s.is_empty() {
        return Vec::new();
    }
    let trimmed = s.strip_suffix('\n').unwrap_or(s);
    trimmed.split('\n').collect()
}

fn is_file_header(line: &str) -> bool {
    line.starts_with("--- ")
        || line.starts_with("+++ ")
        || line.starts_with("diff ")
        || line.starts_with("index ")
}

fn malformed(detail: &str) -> OrchestratorError {
    OrchestratorError::Invalid {
        what: "mutant diff",
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_a_single_line_replacement() {
        let original = "fn f(x: i32) -> bool {\n    x <= 10\n}\n";
        let diff = "@@ -2,1 +2,1 @@\n-    x <= 10\n+    x < 10\n";
        let out = apply_unified_diff(original, diff).unwrap();
        assert_eq!(out, "fn f(x: i32) -> bool {\n    x < 10\n}\n");
    }

    #[test]
    fn applies_addition_and_removal() {
        let original = "a\nb\nc\n";
        let diff = "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n";
        assert_eq!(apply_unified_diff(original, diff).unwrap(), "a\nB\nc\n");
    }

    #[test]
    fn pure_insertion_keeps_surrounding_lines() {
        let original = "line1\nline2\n";
        let diff = "@@ -1,2 +1,3 @@\n line1\n+inserted\n line2\n";
        assert_eq!(
            apply_unified_diff(original, diff).unwrap(),
            "line1\ninserted\nline2\n"
        );
    }

    #[test]
    fn fails_closed_on_context_mismatch() {
        let original = "a\nb\nc\n";
        // Claims line 2 is "X" but it is "b" → reject (no corrupted output).
        let diff = "@@ -2,1 +2,1 @@\n-X\n+Y\n";
        assert!(apply_unified_diff(original, diff).is_err());
    }

    #[test]
    fn fails_closed_on_malformed_header() {
        let original = "a\n";
        assert!(apply_unified_diff(original, "@@ garbage @@\n+x\n").is_err());
        assert!(apply_unified_diff(original, "@@ -1 +1 @@\nx no op prefix\n").is_err());
    }

    #[test]
    fn fails_closed_on_truncated_hunk() {
        let original = "a\nb\n";
        // Declares 2 old lines but provides only 1 body line.
        let diff = "@@ -1,2 +1,2 @@\n a\n";
        assert!(apply_unified_diff(original, diff).is_err());
    }

    #[test]
    fn tolerates_file_headers_and_default_counts() {
        let original = "x\n";
        let diff = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n";
        assert_eq!(apply_unified_diff(original, diff).unwrap(), "y\n");
    }

    #[test]
    fn fails_closed_on_out_of_order_hunks() {
        let original = "a\nb\nc\nd\n";
        // Second hunk targets line 1, before the first hunk already consumed up to line 3 → reject
        // rather than silently misapply at the current cursor (T1/F9).
        let diff = "@@ -3,1 +3,1 @@\n-c\n+C\n@@ -1,1 +1,1 @@\n-a\n+A\n";
        assert!(apply_unified_diff(original, diff).is_err());
    }

    #[test]
    fn rejects_old_start_zero_with_nonempty_old_range() {
        // old_start 0 is only valid for a pure insertion (old_count 0).
        assert!(apply_unified_diff("a\n", "@@ -0,1 +1,1 @@\n-a\n+b\n").is_err());
    }

    #[test]
    fn handles_empty_context_lines() {
        let original = "a\n\nb\n";
        let diff = "@@ -1,3 +1,3 @@\n a\n\n-b\n+B\n";
        assert_eq!(apply_unified_diff(original, diff).unwrap(), "a\n\nB\n");
    }
}
