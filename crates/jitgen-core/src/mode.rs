//! Run mode and generation strategy (see ADR-0002).

use serde::{Deserialize, Serialize};

/// What kind of test we are trying to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Tests that **pass** on `head` — classic, landable. Default & non-destructive.
    #[default]
    Harden,
    /// Tests that **fail** on `head` while passing on `base` (a *weak catch*); report-only.
    Catch,
}

/// How candidate tests are generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    /// Choose automatically from the mode (`harden`→`Harden`, `catch`→`IntentAware`).
    #[default]
    Auto,
    /// Generate tests that pass on `head`.
    Harden,
    /// Treat the diff itself as a mutant and generate tests that distinguish it from the parent.
    DodgyDiff,
    /// Infer diff risks → construct mutants → generate mutant-killing tests → replay on `head`.
    IntentAware,
}

impl Strategy {
    /// Resolve `Auto` to a concrete strategy given the run mode.
    pub fn resolve(self, mode: Mode) -> Strategy {
        match self {
            Strategy::Auto => match mode {
                Mode::Harden => Strategy::Harden,
                Mode::Catch => Strategy::IntentAware,
            },
            other => other,
        }
    }
}

impl Mode {
    /// Stable lowercase string form (for persistence / display).
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Harden => "harden",
            Mode::Catch => "catch",
        }
    }

    /// Parse from the [`Mode::as_str`] form.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "harden" => Some(Mode::Harden),
            "catch" => Some(Mode::Catch),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_roundtrips() {
        for m in [Mode::Harden, Mode::Catch] {
            assert_eq!(Mode::parse(m.as_str()), Some(m));
        }
        assert_eq!(Mode::parse("bogus"), None);
    }

    #[test]
    fn defaults_are_safe() {
        assert_eq!(Mode::default(), Mode::Harden);
        assert_eq!(Strategy::default(), Strategy::Auto);
    }

    #[test]
    fn auto_resolves_per_mode() {
        assert_eq!(Strategy::Auto.resolve(Mode::Harden), Strategy::Harden);
        assert_eq!(Strategy::Auto.resolve(Mode::Catch), Strategy::IntentAware);
        // Explicit strategy is preserved.
        assert_eq!(
            Strategy::DodgyDiff.resolve(Mode::Catch),
            Strategy::DodgyDiff
        );
    }

    #[test]
    fn serde_uses_expected_tokens() {
        assert_eq!(serde_json::to_string(&Mode::Catch).unwrap(), "\"catch\"");
        assert_eq!(
            serde_json::to_string(&Strategy::IntentAware).unwrap(),
            "\"intent-aware\""
        );
    }
}
