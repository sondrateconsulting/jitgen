//! Offline provider that **replays recorded responses** — for `jitgen demo` and deterministic tests.
//!
//! [`RecordedProvider`] returns canned LLM output from a fixed, ordered list, indexed by the request's
//! `attempt` and **clamped to the last** entry so it is idempotent under any extra repair call. It
//! opens no socket and reads no key (offline, like [`MockProvider`](crate::MockProvider)).
//!
//! Security: it is constructed **only** by trusted code (the demo command / tests) over **embedded**
//! fixture data, and is **never** wired into [`make_provider`](crate::make_provider) or `ProviderKind`.
//! So a hostile repo can never select it: the offline-mock default and the structural trust split are
//! untouched (ADR-0008/ADR-0010). It does not judge whether the replayed text *catches* anything — the
//! real sandbox + rules assessor do (the demo's whole point: only the LLM text is replayed).

use crate::provider::{LlmProvider, LlmRequest, LlmResponse, Result};

/// An offline provider that replays a fixed, ordered list of recorded responses.
#[derive(Debug, Clone)]
pub struct RecordedProvider {
    /// Recorded raw responses, consumed by `attempt` index (clamped to the last).
    responses: Vec<String>,
}

impl RecordedProvider {
    /// Replay a sequence of recorded responses. `attempt` selects the response, clamped to the last so
    /// a repair retry past the end re-serves the final recorded response (idempotent). An empty list
    /// degrades to an empty response (a safe no-op: the candidate parser then yields nothing) — callers
    /// pass non-empty embedded fixtures.
    pub fn new(responses: Vec<String>) -> Self {
        Self { responses }
    }

    /// Convenience for the common single-response demo/test case.
    pub fn single(response: impl Into<String>) -> Self {
        Self::new(vec![response.into()])
    }
}

impl LlmProvider for RecordedProvider {
    fn name(&self) -> &str {
        "recorded"
    }

    fn generate(&self, req: &LlmRequest) -> Result<LlmResponse> {
        // Index by attempt, clamped to the last recorded response → idempotent under a repair retry.
        let raw = if self.responses.is_empty() {
            String::new()
        } else {
            let idx = (req.attempt as usize).min(self.responses.len() - 1);
            self.responses[idx].clone()
        };
        Ok(LlmResponse { raw })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_context::Prompt;
    use jitgen_core::{Mode, Strategy};

    fn req(attempt: u16) -> LlmRequest {
        LlmRequest {
            prompt: Prompt {
                system: "s".into(),
                user: "u".into(),
            },
            mode: Mode::Catch,
            strategy: Strategy::DodgyDiff,
            language: "demo".into(),
            symbol: None,
            attempt,
            repair_feedback: None,
        }
    }

    #[test]
    fn name_is_recorded_not_mock() {
        // Guards the invariant that this provider is distinguishable and never masquerades as the mock.
        assert_eq!(RecordedProvider::single("x").name(), "recorded");
        assert_ne!(RecordedProvider::single("x").name(), "mock");
    }

    #[test]
    fn single_replays_the_same_response_for_any_attempt() {
        let p = RecordedProvider::single("the recorded test");
        assert_eq!(p.generate(&req(0)).unwrap().raw, "the recorded test");
        // Clamped: a repair retry (attempt > 0) re-serves the only response (idempotent).
        assert_eq!(p.generate(&req(3)).unwrap().raw, "the recorded test");
    }

    #[test]
    fn sequence_replays_in_order_then_clamps_to_last() {
        let p = RecordedProvider::new(vec!["r0".into(), "r1".into(), "r2".into()]);
        assert_eq!(p.generate(&req(0)).unwrap().raw, "r0");
        assert_eq!(p.generate(&req(1)).unwrap().raw, "r1");
        assert_eq!(p.generate(&req(2)).unwrap().raw, "r2");
        // Past the end clamps to the last (idempotent repair convergence).
        assert_eq!(p.generate(&req(7)).unwrap().raw, "r2");
    }

    #[test]
    fn empty_list_degrades_to_empty_response_without_panicking() {
        // Defensive: misuse is a safe no-op (empty candidate → dropped downstream), never a panic.
        let p = RecordedProvider::new(vec![]);
        assert_eq!(p.generate(&req(0)).unwrap().raw, "");
        assert_eq!(p.generate(&req(5)).unwrap().raw, "");
    }
}
