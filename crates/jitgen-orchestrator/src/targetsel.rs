//! Explainable, risk-ranked target selection (the paper's DRS targeter analogue, ADR-0002).
//!
//! The ML-trained Diff-Risk-Score from the paper is out of scope; instead we use a small, **fully
//! explainable** heuristic that combines the adapter's per-target risk with transparent diff signals
//! (symbol kind, changed-span size). Every selected target carries a human-readable rationale, which
//! `analyze` surfaces as a dry-run plan. Targets are then ranked high-to-low and capped to the trusted
//! `max_tests` budget.

use jitgen_core::{SymbolKind, Target};

/// A target plus its computed priority score and an explanation.
#[derive(Debug, Clone, PartialEq)]
pub struct RankedTarget {
    /// The selected target.
    pub target: Target,
    /// Composite priority score in `[0,1]` (higher = generate first).
    pub score: f64,
    /// Human-readable explanation of the score (for `analyze`).
    pub rationale: String,
}

/// Weight of a symbol kind: a named function/method is a higher-value test target than a bare hunk.
fn kind_weight(kind: SymbolKind) -> f64 {
    match kind {
        SymbolKind::Function | SymbolKind::Method => 1.0,
        SymbolKind::Class => 0.9,
        SymbolKind::Module => 0.7,
        SymbolKind::Hunk => 0.6,
    }
}

/// Lines spanned by the target (1-based inclusive).
fn span_lines(t: &Target) -> u32 {
    t.span.end.saturating_sub(t.span.start) + 1
}

/// Rank `targets` high-to-low by an explainable composite score and cap to `max_tests`. A
/// `max_tests` of 0 selects nothing (a hard budget). Ties break by path then id for determinism.
pub fn select(targets: Vec<Target>, max_tests: u32) -> Vec<RankedTarget> {
    let mut ranked: Vec<RankedTarget> = targets.into_iter().map(rank_one).collect();
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.target.path.cmp(&b.target.path))
            .then_with(|| a.target.id.as_str().cmp(b.target.id.as_str()))
    });
    ranked.truncate(max_tests as usize);
    ranked
}

fn rank_one(target: Target) -> RankedTarget {
    let adapter_risk = target.risk.get();
    let kw = kind_weight(target.kind);
    let lines = span_lines(&target);
    // More changed lines → marginally higher risk, saturating at 50 lines.
    let size_factor = (f64::from(lines) / 50.0).min(1.0);

    let score = (0.5 * adapter_risk + 0.35 * kw + 0.15 * size_factor).clamp(0.0, 1.0);
    let symbol = target.symbol.as_deref().unwrap_or("(hunk)");
    let rationale = format!(
        "score={score:.2} = 0.50*adapter_risk({adapter_risk:.2}) + 0.35*kind({:?}={kw:.2}) \
         + 0.15*size({lines}ln={size_factor:.2}); symbol={symbol}; path={}",
        target.kind, target.path
    );
    RankedTarget {
        target,
        score,
        rationale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{AdapterId, LineRange, RiskScore, TargetId};

    fn target(id: &str, path: &str, kind: SymbolKind, risk: f64, span: (u32, u32)) -> Target {
        Target {
            id: TargetId::new(id),
            adapter: AdapterId::new("rust"),
            path: path.into(),
            symbol: if kind == SymbolKind::Hunk {
                None
            } else {
                Some("sym".into())
            },
            kind,
            span: LineRange::new(span.0, span.1).unwrap(),
            risk: RiskScore::new(risk).unwrap(),
        }
    }

    #[test]
    fn ranks_high_risk_function_above_low_risk_hunk() {
        let targets = vec![
            target("t0", "z.rs", SymbolKind::Hunk, 0.2, (1, 1)),
            target("t1", "a.rs", SymbolKind::Function, 0.9, (1, 30)),
        ];
        let ranked = select(targets, 10);
        assert_eq!(ranked.len(), 2);
        // The high-risk function comes first.
        assert_eq!(ranked[0].target.id.as_str(), "t1");
        assert!(ranked[0].score > ranked[1].score);
        assert!(ranked[0].rationale.contains("adapter_risk(0.90)"));
    }

    #[test]
    fn caps_to_max_tests_budget() {
        let targets = (0..5)
            .map(|i| {
                target(
                    &format!("t{i}"),
                    &format!("f{i}.rs"),
                    SymbolKind::Function,
                    0.5,
                    (1, 1),
                )
            })
            .collect();
        assert_eq!(select(targets, 2).len(), 2);
    }

    #[test]
    fn zero_budget_selects_nothing() {
        let targets = vec![target("t0", "a.rs", SymbolKind::Function, 0.9, (1, 1))];
        assert!(select(targets, 0).is_empty());
    }

    #[test]
    fn ordering_is_deterministic_on_ties() {
        // Equal scores → stable order by path then id.
        let targets = vec![
            target("t1", "b.rs", SymbolKind::Function, 0.5, (1, 1)),
            target("t0", "a.rs", SymbolKind::Function, 0.5, (1, 1)),
        ];
        let ranked = select(targets, 10);
        assert_eq!(ranked[0].target.path, "a.rs");
        assert_eq!(ranked[1].target.path, "b.rs");
    }
}
