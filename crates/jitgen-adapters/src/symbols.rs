//! Tree-sitter symbol extraction: map changed line ranges to the smallest enclosing named
//! declaration, with a line-range fallback for languages without a grammar (ADR-0007).

use crate::lang::Lang;
use jitgen_core::{AdapterId, LineRange, RiskScore, SymbolKind, Target, TargetId};
use tree_sitter::{Node, Parser};

fn next_id(seq: &mut u32) -> TargetId {
    let v = *seq;
    *seq += 1;
    TargetId::new(format!("t{v}"))
}

/// Max source size handed to tree-sitter; larger files fall back to hunk targets (DoS bound; F4/S1 #1).
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
/// Max changed ranges processed per file with the grammar (bounds tree rescans).
const MAX_HUNKS: usize = 1000;
/// Tree-sitter parse timeout; on timeout we fall back to hunk targets.
const PARSE_TIMEOUT_MICROS: u64 = 1_000_000;
/// Hard cap on tree descent depth (defensive; AST depth is normally small).
const MAX_DESCENT: usize = 10_000;

/// Extract [`Target`]s for one changed file. Uses the grammar when `lang` is `Some` and parsing
/// succeeds; any changed range without an enclosing symbol (and all ranges when there is no grammar)
/// becomes a `Hunk` target so nothing is silently dropped.
pub fn extract_targets(
    lang: Option<Lang>,
    source: &[u8],
    path: &str,
    adapter: &AdapterId,
    hunks: &[LineRange],
    seq: &mut u32,
) -> Vec<Target> {
    if hunks.is_empty() {
        return Vec::new();
    }
    if let Some(lang) = lang {
        if let Some(targets) = extract_with_grammar(lang, source, path, adapter, hunks, seq) {
            return targets;
        }
    }
    fallback_hunks(path, adapter, hunks, seq)
}

fn extract_with_grammar(
    lang: Lang,
    source: &[u8],
    path: &str,
    adapter: &AdapterId,
    hunks: &[LineRange],
    seq: &mut u32,
) -> Option<Vec<Target>> {
    // Too large to parse safely → hunk fallback (DoS bound; source already capped at intake, this
    // is defense in depth).
    if source.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(&lang.ts_language()).ok()?;
    parser.set_timeout_micros(PARSE_TIMEOUT_MICROS);
    let tree = parser.parse(source, None)?; // `None` on timeout → hunk fallback
    let root = tree.root_node();
    let kinds = lang.symbol_kinds();

    let mut targets: Vec<Target> = Vec::new();
    let mut unmatched: Vec<LineRange> = Vec::new();

    // Bound the number of ranges processed with the grammar (each is an O(depth) tree descent).
    let capped = &hunks[..hunks.len().min(MAX_HUNKS)];
    for hunk in capped {
        let row = hunk.start.saturating_sub(1) as usize; // 0-based row of the hunk start
        match enclosing(root, row, kinds) {
            Some((node, kind)) => {
                let start = (node.start_position().row + 1) as u32;
                let end = (node.end_position().row + 1) as u32;
                match LineRange::new(start, end) {
                    Ok(span) if !targets.iter().any(|t| t.path == path && t.span == span) => {
                        targets.push(Target {
                            id: next_id(seq),
                            adapter: adapter.clone(),
                            path: path.to_string(),
                            symbol: node_name(&node, source),
                            kind,
                            span,
                            risk: symbol_risk(span, capped),
                        });
                    }
                    Ok(_) => {} // already captured this symbol
                    Err(_) => unmatched.push(*hunk),
                }
            }
            None => unmatched.push(*hunk),
        }
    }
    // Any ranges beyond the cap fall back to hunk targets (never silently dropped).
    if hunks.len() > MAX_HUNKS {
        unmatched.extend_from_slice(&hunks[MAX_HUNKS..]);
    }
    targets.extend(fallback_hunks(path, adapter, &unmatched, seq));
    Some(targets)
}

/// Innermost interesting (named-declaration) node containing 0-based `row`. **Iterative** explicit-
/// stack DFS over all row-containing nodes (no call recursion; visit-budget bounded) — picks the
/// smallest-byte-span interesting node, so a same-line declaration (`const f = () => {}`) resolves to
/// the function, not a hunk (F4/T3 review #1), and a deep hostile AST cannot overflow the stack.
fn enclosing<'a>(
    root: Node<'a>,
    row: usize,
    kinds: &[(&str, SymbolKind)],
) -> Option<(Node<'a>, SymbolKind)> {
    let contains = |n: &Node<'_>| n.start_position().row <= row && row <= n.end_position().row;
    if !contains(&root) {
        return None;
    }
    let mut best: Option<(Node<'a>, SymbolKind)> = None;
    let mut best_len = usize::MAX;
    let mut stack: Vec<Node<'a>> = vec![root];
    let mut cursor = root.walk();
    let mut budget = MAX_DESCENT;
    while let Some(node) = stack.pop() {
        budget = budget.saturating_sub(1);
        if budget == 0 {
            break;
        }
        if let Some((_, sk)) = kinds.iter().find(|(k, _)| *k == node.kind()) {
            let len = node.end_byte().saturating_sub(node.start_byte());
            if len < best_len {
                best = Some((node, *sk));
                best_len = len;
            }
        }
        cursor.reset(node);
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if contains(&child) {
                    stack.push(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    best
}

fn node_name(node: &Node<'_>, source: &[u8]) -> Option<String> {
    if let Some(name) = node.child_by_field_name("name") {
        return name.utf8_text(source).ok().map(|s| s.to_string());
    }
    // Anonymous function bound to a declarator/property/assignment: recover the bound name from the
    // parent (e.g. `const f = () => {}`, `obj.f = function() {}`) — F4/T1 review #3.
    let parent = node.parent()?;
    let field = match parent.kind() {
        "variable_declarator" => "name",
        "pair" | "public_field_definition" | "field_definition" => "key",
        "assignment_expression" => "left",
        _ => return None,
    };
    parent
        .child_by_field_name(field)
        .and_then(|n| n.utf8_text(source).ok())
        .map(|s| s.to_string())
}

/// Explainable risk: fraction of the symbol's lines that changed, clamped to `[0.05, 1.0]`.
fn symbol_risk(span: LineRange, hunks: &[LineRange]) -> RiskScore {
    let span_lines = (span.end - span.start + 1) as f64;
    let mut changed = 0u32;
    for h in hunks {
        let lo = h.start.max(span.start);
        let hi = h.end.min(span.end);
        if lo <= hi {
            changed += hi - lo + 1;
        }
    }
    let ratio = (changed as f64 / span_lines).clamp(0.05, 1.0);
    RiskScore::new(ratio).unwrap_or_else(|_| RiskScore::new(0.5).expect("0.5 is valid"))
}

fn fallback_hunks(
    path: &str,
    adapter: &AdapterId,
    hunks: &[LineRange],
    seq: &mut u32,
) -> Vec<Target> {
    hunks
        .iter()
        .map(|h| Target {
            id: next_id(seq),
            adapter: adapter.clone(),
            path: path.to_string(),
            symbol: None,
            kind: SymbolKind::Hunk,
            span: *h,
            risk: RiskScore::new(0.5).expect("0.5 is valid"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lr(a: u32, b: u32) -> LineRange {
        LineRange::new(a, b).unwrap()
    }

    #[test]
    fn extracts_enclosing_rust_function() {
        let src = b"fn alpha() {\n    let x = 1;\n}\n\nfn beta() {\n    let y = 2;\n}\n";
        let adapter = AdapterId::new("rust");
        let mut seq = 0;
        // Change on line 2 → inside `alpha`.
        let targets = extract_targets(
            Some(Lang::Rust),
            src,
            "src/a.rs",
            &adapter,
            &[lr(2, 2)],
            &mut seq,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].symbol.as_deref(), Some("alpha"));
        assert_eq!(targets[0].kind, SymbolKind::Function);
        assert_eq!(targets[0].span, lr(1, 3));
    }

    #[test]
    fn extracts_python_class_and_dedups_multiline_hunk() {
        let src = b"class Foo:\n    def bar(self):\n        return 1\n";
        let adapter = AdapterId::new("python");
        let mut seq = 0;
        // A hunk spanning the method body; start line 2 → inside `bar` (method/function).
        let targets = extract_targets(
            Some(Lang::Python),
            src,
            "m.py",
            &adapter,
            &[lr(2, 3)],
            &mut seq,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].symbol.as_deref(), Some("bar"));
        assert_eq!(targets[0].kind, SymbolKind::Function);
    }

    #[test]
    fn falls_back_to_hunk_without_grammar() {
        let adapter = AdapterId::new("generic");
        let mut seq = 0;
        let targets = extract_targets(
            None,
            b"anything",
            "x.weird",
            &adapter,
            &[lr(1, 4)],
            &mut seq,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, SymbolKind::Hunk);
        assert_eq!(targets[0].symbol, None);
        assert_eq!(targets[0].span, lr(1, 4));
    }

    #[test]
    fn change_outside_any_symbol_falls_back_to_hunk() {
        // A top-level change (line 1) with no enclosing function → Hunk target.
        let src = b"const TOP = 1;\nfunction f() {\n  return 2;\n}\n";
        let adapter = AdapterId::new("typescript");
        let mut seq = 0;
        let targets = extract_targets(
            Some(Lang::TypeScript),
            src,
            "a.ts",
            &adapter,
            &[lr(1, 1)],
            &mut seq,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, SymbolKind::Hunk);
    }

    #[test]
    fn extracts_ts_arrow_const_with_name() {
        let src = b"const greet = (name: string) => {\n  return name;\n};\n";
        let adapter = AdapterId::new("typescript");
        let mut seq = 0;
        let targets = extract_targets(
            Some(Lang::TypeScript),
            src,
            "a.ts",
            &adapter,
            &[lr(2, 2)],
            &mut seq,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, SymbolKind::Function);
        assert_eq!(targets[0].symbol.as_deref(), Some("greet"));
    }

    #[test]
    fn extracts_same_line_ts_arrow_declaration() {
        // The change is ON the one-line declaration itself (F4/T3 review #1).
        let src = b"const f = () => 1;\nconst g = () => 2;\n";
        let adapter = AdapterId::new("typescript");
        let mut seq = 0;
        let targets = extract_targets(
            Some(Lang::TypeScript),
            src,
            "a.ts",
            &adapter,
            &[lr(1, 1)],
            &mut seq,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, SymbolKind::Function);
        assert_eq!(targets[0].symbol.as_deref(), Some("f"));
    }
}
