//! The LLM-based assessor ("LLM-as-judge").
//!
//! Itself a prompt-injection surface (repo code, test source, and failure logs flow into it), so it is
//! deliberately **weak**: it can only *lower* the rule-derived confidence (the caller takes
//! `rule_prob.min(judge_score)`), never raise it, and it never touches the rule gate (ADR-0002;
//! security.md §2 #7). Its inputs are redacted + fenced (see [`crate::prompts::judge_prompt`]).
//!
//! The verdict is parsed as **strict JSON** (T1/F8 #2): only a JSON object whose `tp_probability` is a
//! finite number is honored. A provider error, non-JSON text, a non-numeric/non-finite value, or a
//! missing key all degrade to a **neutral** score (`1.0` ⇒ `min` is a no-op) — so garbled or hostile
//! judge output cannot move the decision in *either* direction; the deterministic rules stand alone.

use crate::llmstep::request;
use crate::prompts::judge_prompt;
use jitgen_context::redact;
use jitgen_core::{Mode, Strategy};
use jitgen_llm::{extract_code, LlmProvider};
use serde_json::Value;

/// Neutral score: `min(rule, NEUTRAL)` == rule, i.e. the judge contributes nothing.
const NEUTRAL_SCORE: f64 = 1.0;
const MAX_RATIONALE: usize = 240;

/// The LLM judge's contribution.
pub(crate) struct JudgeSignal {
    /// TP probability in `[0,1]`; only ever *lowers* the combined confidence.
    pub score: f64,
    /// Redacted, control-stripped, capped rationale (may be empty).
    pub rationale: String,
}

impl JudgeSignal {
    /// A neutral signal (`NEUTRAL_SCORE` ⇒ `min` is a no-op): the judge contributes nothing.
    pub(crate) fn neutral(rationale: &str) -> Self {
        Self {
            score: NEUTRAL_SCORE,
            rationale: rationale.to_string(),
        }
    }
}

/// Ask the judge for a TP probability over already-redacted weak-catch `evidence`. Infallible: a
/// provider error or non-strict-JSON output yields a neutral signal.
pub(crate) fn judge(provider: &dyn LlmProvider, evidence: &str) -> JudgeSignal {
    let req = request(
        judge_prompt(evidence),
        Mode::Catch,
        Strategy::IntentAware,
        "assessment",
        None,
    );
    let resp = match provider.generate(&req) {
        Ok(resp) => resp,
        Err(_) => {
            return JudgeSignal::neutral("llm judge unavailable; using deterministic rules only")
        }
    };
    // Strict JSON only: anything that is not a JSON object is treated as no signal at all.
    match serde_json::from_str::<Value>(&extract_code(&resp.raw)) {
        Ok(value) => JudgeSignal {
            score: parse_probability(&value).unwrap_or(NEUTRAL_SCORE),
            rationale: parse_rationale(&value),
        },
        Err(_) => {
            JudgeSignal::neutral("unparseable judge output (not strict JSON); using rules only")
        }
    }
}

/// Read `tp_probability` as a finite JSON number and clamp to `[0,1]`. An out-of-range value (e.g.
/// `5.0`) clamps to `1.0` (neutral — cannot raise); a negative clamps to `0.0` (lowers). A missing key,
/// a non-number (string/bool/null), or a non-finite value ⇒ `None` (neutral). JSON syntax forbids
/// `NaN`/`Infinity`, so those never even reach here (the `from_str` above rejects them).
fn parse_probability(value: &Value) -> Option<f64> {
    let n = value.get("tp_probability")?.as_f64()?;
    if !n.is_finite() {
        return None;
    }
    Some(n.clamp(0.0, 1.0))
}

/// Extract the `rationale` string; redacted, control-stripped, capped. Missing/non-string ⇒ empty.
fn parse_rationale(value: &Value) -> String {
    let raw = value.get("rationale").and_then(Value::as_str).unwrap_or("");
    let red = redact(raw).text;
    red.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_RATIONALE)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::ScriptedProvider;
    use jitgen_llm::{LlmResponse, MockProvider};

    fn scripted(raw: &'static str) -> ScriptedProvider {
        ScriptedProvider::new(
            "judge",
            Box::new(move |_| {
                Ok(LlmResponse {
                    raw: raw.to_string(),
                })
            }),
        )
    }

    #[test]
    fn parses_in_range_probability_and_rationale() {
        let p = scripted(
            "```json\n{\"tp_probability\": 0.73, \"rationale\": \"plausible off-by-one\"}\n```",
        );
        let s = judge(&p, "evidence");
        assert!((s.score - 0.73).abs() < 1e-9, "{}", s.score);
        assert!(s.rationale.contains("off-by-one"));
    }

    #[test]
    fn out_of_range_high_clamps_to_neutral_one() {
        // A hostile "definitely strong, 5.0" cannot raise: clamps to 1.0 ⇒ min() is a no-op.
        let p = scripted("```\n{\"tp_probability\": 5.0}\n```");
        assert_eq!(judge(&p, "e").score, 1.0);
    }

    #[test]
    fn negative_clamps_to_zero_and_lowers() {
        // Valid JSON with a negative value: clamps to 0.0 (lowering is the safe direction).
        let p = scripted("```\n{\"tp_probability\": -2}\n```");
        assert_eq!(judge(&p, "e").score, 0.0);
    }

    #[test]
    fn malformed_json_is_neutral_not_lowering() {
        // T1/F8 #2: invalid JSON (`0/0`) and a bare, brace-less value must be NEUTRAL, not parsed as a
        // low score — an invalid judge response has no effect in either direction.
        assert_eq!(
            judge(&scripted("```\n{\"tp_probability\": 0/0}\n```"), "e").score,
            NEUTRAL_SCORE
        );
        assert_eq!(
            judge(&scripted("```\ntp_probability: 0.3\n```"), "e").score,
            NEUTRAL_SCORE
        );
        // A stringified number is not a JSON number ⇒ neutral (strict).
        assert_eq!(
            judge(&scripted("```\n{\"tp_probability\": \"0.1\"}\n```"), "e").score,
            NEUTRAL_SCORE
        );
    }

    #[test]
    fn json_infinity_and_nan_are_rejected_as_neutral() {
        // JSON forbids these tokens, so `from_str` fails ⇒ neutral (cannot raise via `Infinity`).
        assert_eq!(
            judge(&scripted("```\n{\"tp_probability\": Infinity}\n```"), "e").score,
            NEUTRAL_SCORE
        );
        assert_eq!(
            judge(&scripted("```\n{\"tp_probability\": NaN}\n```"), "e").score,
            NEUTRAL_SCORE
        );
    }

    #[test]
    fn unparseable_is_neutral() {
        // The real MockProvider emits a test, not JSON ⇒ neutral (deterministic rules stand).
        let s = judge(&MockProvider::new(), "evidence");
        assert_eq!(s.score, NEUTRAL_SCORE);
    }

    #[test]
    fn provider_error_is_neutral() {
        let p = ScriptedProvider::new(
            "err",
            Box::new(|_| Err(jitgen_llm::GenerationError::Provider("boom".into()))),
        );
        let s = judge(&p, "e");
        assert_eq!(s.score, NEUTRAL_SCORE);
        assert!(s.rationale.contains("unavailable"));
    }

    #[test]
    fn rationale_is_redacted_and_control_stripped() {
        let p = scripted(
            "```\n{\"tp_probability\":0.5,\"rationale\":\"see ghp_0123456789abcdefghijABCDEFGHIJ012345 bad\"}\n```",
        );
        let s = judge(&p, "e");
        assert!(!s.rationale.contains("ghp_0123456789"), "{}", s.rationale);
    }
}
