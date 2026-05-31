//! macOS `sandbox-exec` (SBPL) profile generation for the OS-sandbox tier.
//!
//! The profile is **deny-by-default**, denies **all** network, allows reads broadly (so language
//! toolchains and shared libraries load), and allows writes **only** under the canonical overlay and
//! the synthetic temp dir. It is built deterministically from absolute, caller-canonicalized paths so
//! the security-critical text is reviewable and unit-testable without spawning anything.
//!
//! `sandbox-exec` is Apple-deprecated but functional and the best local macOS option ([ADR-0003]).

use crate::error::{Result, SandboxError};
use std::path::Path;

/// Render an SBPL profile confining writes to `overlay` and `tmp` and denying all network.
///
/// Both paths must be absolute (the caller canonicalizes them); a relative path is rejected rather
/// than silently producing an unconfined profile.
pub fn render_profile(overlay: &Path, tmp: &Path) -> Result<String> {
    let overlay = abs(overlay)?;
    let tmp = abs(tmp)?;
    Ok(format!(
        "(version 1)\n\
         (deny default)\n\
         (allow process-fork)\n\
         (allow process-exec)\n\
         (allow signal (target self))\n\
         (allow sysctl-read)\n\
         (allow mach-lookup)\n\
         (allow file-read*)\n\
         (allow file-write*\n\
         \x20 (subpath {overlay})\n\
         \x20 (subpath {tmp}))\n\
         (deny network*)\n",
        overlay = sbpl_string(&overlay),
        tmp = sbpl_string(&tmp),
    ))
}

/// Require an absolute path, returning its lossless string form.
fn abs(p: &Path) -> Result<String> {
    if !p.is_absolute() {
        return Err(SandboxError::NonAbsolutePath(p.display().to_string()));
    }
    Ok(p.to_string_lossy().into_owned())
}

/// Quote a path as an SBPL string literal, escaping `\` and `"` so a path can never break out of the
/// quoted token (defense-in-depth; jitgen-owned overlay paths do not normally contain these).
fn sbpl_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn profile_denies_network_and_defaults() {
        let p = render_profile(
            Path::new("/tmp/overlay"),
            Path::new("/tmp/overlay/.jitgen-tmp"),
        )
        .unwrap();
        assert!(p.contains("(deny default)"));
        assert!(p.contains("(deny network*)"));
    }

    #[test]
    fn profile_confines_writes_to_overlay_and_tmp_only() {
        let p = render_profile(Path::new("/o/root"), Path::new("/o/root/tmp")).unwrap();
        assert!(p.contains("(allow file-write*"));
        assert!(p.contains("(subpath \"/o/root\")"));
        assert!(p.contains("(subpath \"/o/root/tmp\")"));
        // Reads are allowed broadly so toolchains load, but writes are not unconfined.
        assert!(p.contains("(allow file-read*)"));
        assert!(
            !p.contains("(allow file-write*)\n"),
            "writes must be subpath-scoped"
        );
    }

    #[test]
    fn relative_paths_are_rejected() {
        let rel = PathBuf::from("relative/overlay");
        assert!(matches!(
            render_profile(&rel, Path::new("/tmp")),
            Err(SandboxError::NonAbsolutePath(_))
        ));
    }

    #[test]
    fn path_with_quote_is_escaped_not_breaking_out() {
        // A contrived path containing a quote must be escaped inside the literal.
        let weird = PathBuf::from("/tmp/ev\"il");
        let p = render_profile(&weird, Path::new("/tmp/t")).unwrap();
        assert!(p.contains("/tmp/ev\\\"il"));
    }
}
