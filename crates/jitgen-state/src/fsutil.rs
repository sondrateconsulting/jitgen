//! Filesystem helpers for durable, safe state persistence (ADR-0005, security §4/§10).

use crate::error::{Result, StateError};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counter for unique temp-file names (combined with pid).
static TEMP_CTR: AtomicU64 = AtomicU64::new(0);

/// Create `dir` (and parents) if missing and tighten its permissions to `0700` on Unix.
///
/// Rejects a pre-existing **symlinked leaf** (an attacker-planted redirect of our state dir). We do
/// not reject symlink *ancestors* here because legitimate system paths (e.g. macOS `/tmp`, `/var`)
/// are symlinks; full per-component `openat` traversal is the F7 overlay-materialization hardening.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() {
            return Err(StateError::Invalid(format!(
                "refusing to use symlinked state path: {}",
                dir.display()
            )));
        }
    }
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

/// Join `rel` under `base`, rejecting absolute paths, `..` traversal, and root/prefix components.
/// `rel` must stay strictly within `base` (security §4). The path need not exist yet.
pub fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    for comp in rel_path.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(StateError::Invalid(format!(
                    "'..' not allowed in artifact path: {rel}"
                )))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(StateError::Invalid(format!(
                    "absolute artifact path not allowed: {rel}"
                )))
            }
        }
    }
    Ok(base.join(rel_path))
}

/// Atomically write `bytes` to `path`: write to a sibling temp file, `fsync`, then `rename`.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| StateError::Invalid(format!("no parent dir for {}", path.display())))?;
    ensure_private_dir(parent)?;
    // Unique temp name in the same directory (so the final rename is atomic). pid + counter avoid
    // collisions across retries and make the name unpredictable enough to pair with O_EXCL.
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| StateError::Invalid(format!("bad file name for {}", path.display())))?;
    let unique = TEMP_CTR.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{file_name}.{}.{unique}.tmp", std::process::id()));
    {
        // `create_new` => O_CREAT|O_EXCL: fails if the path already exists (including a planted
        // symlink), so we never follow or clobber an attacker-controlled temp target (F2/S1 #5).
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    // `rename` replaces a symlink at the destination rather than following it.
    fs::rename(&tmp, path)?;
    // Durability: fsync the containing directory so the new dir entry survives a crash before the
    // artifact hash is recorded in SQLite (F2/T1 review #5). Unix-only; elsewhere a best-effort no-op.
    #[cfg(unix)]
    {
        let dir = fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

/// Lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_traversal_and_absolute() {
        let base = Path::new("/tmp/run");
        assert!(safe_join(base, "../escape").is_err());
        assert!(safe_join(base, "/etc/passwd").is_err());
        assert!(safe_join(base, "a/../../b").is_err());
        let ok = safe_join(base, "reports/out.json").unwrap();
        assert!(ok.ends_with("reports/out.json"));
    }

    #[test]
    fn sha256_is_known_vector() {
        // SHA-256("") well-known digest.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
