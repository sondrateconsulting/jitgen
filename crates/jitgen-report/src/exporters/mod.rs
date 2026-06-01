//! Output renderers. Each takes a [`crate::RunReport`] and returns a `String` in its format. Every
//! renderer routes untrusted strings through [`crate::escape`] so a hostile test name / path /
//! rationale is rendered as data, never markup or terminal controls (security.md §10).

pub(crate) mod human;
pub(crate) mod json;
pub(crate) mod junit;
pub(crate) mod markdown;
pub(crate) mod patch;
pub(crate) mod sarif;
