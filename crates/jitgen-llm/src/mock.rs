//! Deterministic offline mock provider (ADR-0008).
//!
//! Emits a plausible, language-appropriate test in a fenced code block, seeded deterministically by
//! a hash of the request. No network, no API keys — the default for all tests/CI. Output varies by
//! attempt so the F8 repair loop can drive generate→repair scenarios.

use crate::provider::{LlmProvider, LlmRequest, LlmResponse, Result};
use std::hash::{Hash, Hasher};

/// Deterministic, offline LLM provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockProvider;

impl MockProvider {
    /// Construct the mock provider.
    pub fn new() -> Self {
        Self
    }
}

impl LlmProvider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }

    fn generate(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let seed = deterministic_seed(req);
        Ok(LlmResponse {
            raw: render(&req.language, req.symbol.as_deref(), seed, req.attempt),
        })
    }
}

/// Stable (within a process) seed from the request. `DefaultHasher` uses fixed keys, so identical
/// requests always produce identical output (determinism, not cryptographic).
fn deterministic_seed(req: &LlmRequest) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    req.prompt.system.hash(&mut h);
    req.prompt.user.hash(&mut h);
    req.language.hash(&mut h);
    req.symbol.hash(&mut h);
    req.attempt.hash(&mut h);
    h.finish()
}

fn render(language: &str, symbol: Option<&str>, seed: u64, attempt: u16) -> String {
    let name = symbol.unwrap_or("unit");
    let suffix = seed % 100_000;
    let (tag, code) = match language {
        "rust" => (
            "rust",
            format!("#[test]\nfn jitgen_{name}_{suffix}_{attempt}() {{\n    assert_eq!(1 + 1, 2);\n}}\n"),
        ),
        "python" => (
            "python",
            format!("def test_jitgen_{name}_{suffix}_{attempt}():\n    assert 1 + 1 == 2\n"),
        ),
        "java" => (
            "java",
            format!(
                "@org.junit.Test\npublic void jitgen_{name}_{suffix}_{attempt}() {{\n    \
                 org.junit.Assert.assertEquals(2, 1 + 1);\n}}\n"
            ),
        ),
        "typescript" => (
            "ts",
            format!("test('jitgen {name} {suffix} {attempt}', () => {{\n  expect(1 + 1).toBe(2);\n}});\n"),
        ),
        _ => ("", format!("// jitgen mock test for {name} ({suffix}/{attempt})\n")),
    };
    format!("Here is a generated test:\n\n```{tag}\n{code}```\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_context::Prompt;
    use jitgen_core::{Mode, Strategy};

    fn req(lang: &str, attempt: u16) -> LlmRequest {
        LlmRequest {
            prompt: Prompt {
                system: "system".into(),
                user: "user".into(),
            },
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            language: lang.into(),
            symbol: Some("alpha".into()),
            attempt,
            repair_feedback: None,
        }
    }

    #[test]
    fn is_deterministic() {
        let m = MockProvider::new();
        let a = m.generate(&req("rust", 0)).unwrap();
        let b = m.generate(&req("rust", 0)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn attempt_changes_output() {
        let m = MockProvider::new();
        let a = m.generate(&req("rust", 0)).unwrap();
        let b = m.generate(&req("rust", 1)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn emits_language_appropriate_fenced_test() {
        let m = MockProvider::new();
        assert!(m.generate(&req("rust", 0)).unwrap().raw.contains("#[test]"));
        assert!(m
            .generate(&req("python", 0))
            .unwrap()
            .raw
            .contains("def test_"));
        assert!(m
            .generate(&req("typescript", 0))
            .unwrap()
            .raw
            .contains("```ts"));
    }
}
