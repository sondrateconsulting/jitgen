//! `Secret` — a resolved API key that cannot be logged by accident.
//!
//! The inner value is private to THIS module, which has no submodules. A private field is visible
//! only to the defining module and its descendants, so with no descendants here nothing outside
//! `secret.rs` — not the sibling provider modules, not the crate's tests — can read the raw value
//! except through [`Secret::expose`]. The no-log invariant is thus enforced by the module boundary,
//! not by convention. (The unit tests live in the parent `real` module, a sibling that cannot reach
//! the field.) `Secret` has a redacting `Debug` and deliberately no `Display`.

/// A resolved API key. The raw value is reachable only through [`Secret::expose`]; this type has a
/// redacting `Debug` and deliberately no `Display`.
///
/// SECURITY: do NOT add a `Display` impl, change `Debug` to print the inner value, or add a child
/// module that reads the private field — the module boundary is what keeps the secret unloggable.
/// `Clone` is safe (it does not format the value).
#[derive(Clone)]
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrow the raw secret. Call ONLY where the value must cross a trust boundary (an auth
    /// header); never log, print, or format the returned `&str`.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

// Unit tests deliberately live in the parent `real` module (see `mod.rs`), NOT here: a child module
// would be a descendant of `secret` and could read the private field directly, weakening the
// boundary this type relies on. From the sibling test module they can only use `new`/`expose`.
