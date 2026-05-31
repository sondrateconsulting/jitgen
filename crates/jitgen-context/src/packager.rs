//! Bounded, redacted context assembly.
//!
//! Adds context items in priority order, redacting each (security §3) and enforcing the
//! [`ContextBudget`]: per-file byte cap, max file count, and an approximate total token budget.

use crate::redact::redact;
use jitgen_core::{ContextBudget, ContextBundle, ContextItem, ContextItemKind, TargetId};

/// Rough chars-per-token used to approximate the token budget.
const CHARS_PER_TOKEN: usize = 4;

const TRUNC_MARKER: &str = "…[truncated]";

/// Hard ceiling on bytes fed to the redaction regexes per item, independent of the (usually much
/// smaller) per-file cap. Bounds worst-case regex work even if a future caller (stdout, repair
/// feedback, diffs) passes a very large string, and means we only ever redact bytes we might keep
/// (F5/S1 #3). Git intake already caps blobs at 2 MiB; this is the layer-5 boundary's own bound.
const MAX_REDACT_INPUT_BYTES: usize = 256 * 1024;

/// Minimum length (bytes) of a trailing unbroken token treated as a possibly-split secret at the
/// redaction-window edge and dropped fail-closed (F5/S1 #3).
const DANGLING_TOKEN_MIN: usize = 8;

/// Largest char-boundary prefix of `s` that is at most `max_bytes`.
fn char_boundary_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// When the redaction window cut the input, the final unbroken token may be the head of a secret
/// whose pattern needed more bytes to match. Drop a long trailing token fail-closed so no partial
/// secret is emitted (F5/S1 #3). Conservative: only acts on a single whitespace-free run.
fn drop_trailing_token(s: &str) -> String {
    let cut = match s.char_indices().rev().find(|(_, c)| c.is_whitespace()) {
        Some((i, c)) => i + c.len_utf8(),
        None => 0,
    };
    if s.len() - cut >= DANGLING_TOKEN_MIN {
        format!("{}{TRUNC_MARKER}", &s[..cut])
    } else {
        s.to_string()
    }
}

/// Truncate `s` so the result (incl. the marker) is at most `max_bytes`, on a UTF-8 char boundary
/// (F5/T1 #4: the marker is reserved inside the cap). When the budget is smaller than the marker
/// itself, return a char-boundary prefix of the marker so the result still never exceeds the cap
/// (F5/S1 #4).
fn truncate(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    if max_bytes < TRUNC_MARKER.len() {
        let mut end = max_bytes;
        while end > 0 && !TRUNC_MARKER.is_char_boundary(end) {
            end -= 1;
        }
        return TRUNC_MARKER[..end].to_string();
    }
    let mut end = max_bytes - TRUNC_MARKER.len();
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNC_MARKER}", &s[..end])
}

/// Accumulates redacted, bounded context for one target.
pub struct ContextBuilder {
    budget: ContextBudget,
    items: Vec<ContextItem>,
    redacted: bool,
    used_chars: usize,
}

impl ContextBuilder {
    /// New builder for the given budget.
    pub fn new(budget: ContextBudget) -> Self {
        Self {
            budget,
            items: Vec::new(),
            redacted: false,
            used_chars: 0,
        }
    }

    /// Redact and add an item within budget. Returns `true` if it was added (possibly truncated),
    /// `false` if dropped because the file/token budget is exhausted.
    pub fn add(&mut self, kind: ContextItemKind, path: Option<String>, content: &str) -> bool {
        if self.items.len() >= self.budget.max_files as usize {
            return false;
        }
        let total_budget = self.budget.max_tokens as usize * CHARS_PER_TOKEN;
        let remaining = total_budget.saturating_sub(self.used_chars);
        if remaining == 0 {
            return false;
        }
        // Bound the bytes the regexes ever see BEFORE redacting, so a hostile huge input cannot
        // drive unbounded scanning and we only redact bytes we might keep (F5/S1 #3).
        let window = char_boundary_prefix(content, MAX_REDACT_INPUT_BYTES);
        let red = redact(window);
        if red.redacted {
            self.redacted = true;
        }
        // Everything within the window is now redacted; if the window cut the input, drop a long
        // trailing token fail-closed (it may be a secret the pattern couldn't fully see). Dropping
        // content is a redaction event too, so reflect it in the flag (F5/T2 #2).
        let mut text = red.text;
        if window.len() < content.len() {
            let dropped = drop_trailing_token(&text);
            if dropped != text {
                self.redacted = true;
            }
            text = dropped;
        }
        let cap = (self.budget.max_bytes_per_file as usize).min(remaining);
        let body = truncate(&text, cap);
        // A non-empty input that truncates to nothing (cap smaller than one char / the marker) is a
        // dropped item, not an empty one — don't pollute the bundle with empties (F5/T2 #3).
        if body.is_empty() && !content.is_empty() {
            return false;
        }
        self.used_chars += body.len();
        self.items.push(ContextItem {
            kind,
            path,
            content: body,
        });
        true
    }

    /// Whether any added content was redacted.
    pub fn redacted(&self) -> bool {
        self.redacted
    }

    /// Number of items accumulated.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether no items have been added.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Finalize into a [`ContextBundle`] for `target`.
    pub fn build(self, target: TargetId) -> ContextBundle {
        ContextBundle {
            target,
            items: self.items,
            budget: self.budget,
            redacted: self.redacted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_budget() -> ContextBudget {
        ContextBudget {
            max_tokens: 100,
            max_files: 2,
            max_bytes_per_file: 50,
        }
    }

    #[test]
    fn respects_file_cap() {
        let mut b = ContextBuilder::new(small_budget());
        assert!(b.add(ContextItemKind::ChangedCode, None, "a"));
        assert!(b.add(ContextItemKind::NeighboringCode, None, "b"));
        // Third file exceeds max_files=2.
        assert!(!b.add(ContextItemKind::ExistingTest, None, "c"));
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn redacts_and_flags() {
        let mut b = ContextBuilder::new(ContextBudget::default());
        b.add(
            ContextItemKind::ChangedCode,
            Some("a.rs".into()),
            "API_KEY = longsecretvalue1",
        );
        assert!(b.redacted());
        let bundle = b.build(TargetId::new("t0"));
        assert!(bundle.redacted);
        assert!(!bundle.items[0].content.contains("longsecretvalue1"));
    }

    #[test]
    fn truncates_large_content() {
        let mut b = ContextBuilder::new(small_budget());
        let big = "x".repeat(1000);
        b.add(ContextItemKind::ChangedCode, None, &big);
        // Capped at max_bytes_per_file (50) + marker.
        assert!(b.build(TargetId::new("t0")).items[0].content.len() < 80);
    }

    #[test]
    fn truncate_never_exceeds_tiny_budget() {
        // Including budgets smaller than the marker itself (F5/S1 #4).
        for cap in 0..=TRUNC_MARKER.len() + 2 {
            let out = truncate(&"y".repeat(100), cap);
            assert!(out.len() <= cap, "cap={cap} out.len()={}", out.len());
        }
    }

    #[test]
    fn drop_trailing_token_strips_long_unbroken_tail() {
        assert_eq!(
            drop_trailing_token("ok fine abcdefghij"),
            format!("ok fine {TRUNC_MARKER}")
        );
        // A short trailing token is kept (not secret-shaped).
        assert_eq!(drop_trailing_token("a b c"), "a b c");
    }

    #[test]
    fn char_boundary_prefix_never_splits_utf8() {
        let s = "héllo wörld🌍end";
        for n in 0..=s.len() {
            let p = char_boundary_prefix(s, n);
            assert!(s.starts_with(p));
            assert!(p.len() <= n);
        }
    }

    #[test]
    fn oversized_input_is_bounded_and_panic_free() {
        let mut b = ContextBuilder::new(small_budget());
        let huge = "x".repeat(MAX_REDACT_INPUT_BYTES * 2);
        assert!(b.add(ContextItemKind::ChangedCode, None, &huge));
        // Dropping the window-split trailing token is a redaction event (F5/T2 #2).
        assert!(b.redacted());
        let body = &b.build(TargetId::new("t0")).items[0].content;
        // Bounded by the per-file cap regardless of input size; redaction saw <= the window.
        assert!(body.len() <= 50 + TRUNC_MARKER.len());
    }

    #[test]
    fn zero_byte_cap_drops_nonempty_item() {
        // max_bytes_per_file = 0 must not push an empty item for non-empty input (F5/T2 #3).
        let budget = ContextBudget {
            max_tokens: 100,
            max_files: 4,
            max_bytes_per_file: 0,
        };
        let mut b = ContextBuilder::new(budget);
        assert!(!b.add(ContextItemKind::ChangedCode, None, "real content"));
        assert_eq!(b.len(), 0);
        // An empty input is legitimately an empty item (nothing to drop).
        assert!(b.add(ContextItemKind::ChangedCode, None, ""));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn token_budget_exhaustion_drops_later_items() {
        // Tight token budget: first item consumes it, later items are dropped (not empty-pushed).
        let budget = ContextBudget {
            max_tokens: 4, // 4 * CHARS_PER_TOKEN = 16 chars total
            max_files: 10,
            max_bytes_per_file: 12,
        };
        let mut b = ContextBuilder::new(budget);
        assert!(b.add(ContextItemKind::ChangedCode, None, "abcdefghij")); // 10 chars
        assert!(b.add(ContextItemKind::NeighboringCode, None, "klmnop")); // fits remaining 6
                                                                          // Budget now exhausted; further non-empty adds are dropped.
        assert!(!b.add(ContextItemKind::ExistingTest, None, "qrstuv"));
        let total: usize = b
            .build(TargetId::new("t0"))
            .items
            .iter()
            .map(|i| i.content.len())
            .sum();
        assert!(total <= 16, "total={total}");
    }
}
