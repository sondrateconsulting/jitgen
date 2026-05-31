//! Current `uid:gid` lookup for the container `--user` flag.
//!
//! Containers run as root by default; to keep an attacker-controlled test off root (and so writes to
//! the host-owned overlay bind mount carry the caller's ownership), the orchestrator runs the
//! container as the invoking user. `std` exposes no `getuid`/`getgid` without the `libc` crate, and
//! this crate is dependency-light and `#![forbid(unsafe_code)]`, so we read them from `id(1)`.
//!
//! `id` is resolved from a **trusted system dir** ([`crate::which`]), never the inherited `PATH` — a
//! hostile repo dir on `PATH` could otherwise ship a fake `id` that prints `0`, fabricating a root
//! `--user` value (S2/F7 P3). Returns `None` off-unix or on any failure; container planning then
//! **fails closed** (it refuses to run without an explicit non-root `--user`), so a `None` here can
//! never silently become container-root.

#[cfg(unix)]
pub fn current_uid_gid() -> Option<String> {
    let uid = id_value("-u")?;
    let gid = id_value("-g")?;
    // Refuse root: containers must run as a non-root user, and `plan_container` rejects a `0:*`
    // pair anyway — returning `None` here makes the "running as root" case fail closed (with a clear
    // `MissingContainerUser`) rather than silently produce `--user 0:0` (T1/F7 P3).
    if uid.bytes().all(|b| b == b'0') {
        return None;
    }
    Some(format!("{uid}:{gid}"))
}

#[cfg(not(unix))]
pub fn current_uid_gid() -> Option<String> {
    None
}

#[cfg(unix)]
fn id_value(flag: &str) -> Option<String> {
    use std::process::{Command, Stdio};
    // Trusted absolute path only (e.g. `/usr/bin/id`); never a PATH-resolved bare `id`.
    let id_bin = crate::which::resolve_trusted("id")?;
    let out = Command::new(id_bin)
        .arg(flag)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    // Must be a plain non-empty numeric id; anything else is rejected (never fed to `docker --user`).
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn returns_numeric_nonroot_uid_gid_on_unix() {
        // As a non-root user → a `<nonzero-uid>:<gid>` pair; as root (e.g. a CI container) → `None`
        // by design (containers must not run as root). Accept either, asserting the shape if present.
        match current_uid_gid() {
            Some(u) => {
                let (uid, gid) = u.split_once(':').expect("uid:gid format");
                assert!(uid.bytes().all(|b| b.is_ascii_digit()) && uid.bytes().any(|b| b != b'0'));
                assert!(!gid.is_empty() && gid.bytes().all(|b| b.is_ascii_digit()));
            }
            None => { /* running as root: refusing is the documented behavior */ }
        }
    }
}
