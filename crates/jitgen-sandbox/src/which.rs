//! Trusted resolution of launcher binaries to absolute paths.
//!
//! Sandbox launchers (`sandbox-exec`, `docker`, `bwrap`, …) and the `id` probe are resolved **only**
//! from a hardcoded allowlist of root-owned system bin directories — **never** via the inherited
//! `PATH`. A hostile repository can prepend an attacker-writable directory to `PATH`; if we resolved
//! a bare `docker`/`sandbox-exec` through it, we would spawn a fake launcher and execute the inner
//! command with no isolation at all (silent fail-open). Resolving against fixed trusted dirs makes
//! that impossible without root on the host. Security §1, [ADR-0003].

use std::path::{Path, PathBuf};

/// Root-owned, non-world-writable system binary directories, in search order. A hostile repo cannot
/// write here without already owning the host. (A symlink *in* one of these dirs — e.g. Docker
/// Desktop's `/usr/local/bin/docker` — is trusted because the link itself is root-owned.)
const TRUSTED_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
];

/// Resolve `program` to an absolute executable path within a trusted system bin dir, or `None`.
///
/// - A bare name (`docker`) is searched across [`TRUSTED_BIN_DIRS`] in order; the inherited `PATH`
///   is never consulted.
/// - An absolute path (`/bin/sh`) is honored **only** if it lies within a trusted dir — so a caller
///   cannot smuggle `/tmp/evil/docker` through.
/// - A relative path with separators (`./docker`, `a/b`) is always rejected.
pub fn resolve_trusted(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let p = Path::new(program);
        if p.is_absolute() && is_in_trusted_dir(p) && is_executable_file(p) {
            return Some(p.to_path_buf());
        }
        return None;
    }
    TRUSTED_BIN_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(program))
        .find(|cand| is_executable_file(cand))
}

/// Whether `p`'s path lies (component-wise) under a trusted bin dir. Checks the literal path, not a
/// canonicalized one: the trust anchor is the root-owned entry in the trusted dir, even if it is a
/// symlink pointing elsewhere.
fn is_in_trusted_dir(p: &Path) -> bool {
    TRUSTED_BIN_DIRS.iter().any(|d| p.starts_with(d))
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // `metadata` follows symlinks, so a trusted-dir symlink to a real binary resolves correctly.
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    p.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_and_untrusted_absolute() {
        assert!(resolve_trusted("./docker").is_none());
        assert!(resolve_trusted("a/b/docker").is_none());
        // An absolute path outside the trusted dirs is refused even if it exists.
        assert!(resolve_trusted("/tmp/evil-docker").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn resolves_known_system_binaries() {
        // `/bin/sh` exists on every unix host and is under a trusted dir.
        let sh = resolve_trusted("sh").expect("sh resolvable from a trusted dir");
        assert!(sh.is_absolute());
        assert!(is_in_trusted_dir(&sh));
        // The same binary by absolute trusted path resolves to itself.
        assert_eq!(resolve_trusted("/bin/sh"), Some(PathBuf::from("/bin/sh")));
    }

    #[cfg(unix)]
    #[test]
    fn bare_name_not_in_trusted_dirs_is_unresolved() {
        // A nonsense name cannot be found in any trusted dir (and PATH is never consulted).
        assert!(resolve_trusted("jitgen-definitely-not-a-real-binary").is_none());
    }
}
