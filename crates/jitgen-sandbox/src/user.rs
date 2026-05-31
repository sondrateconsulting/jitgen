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
    fn returns_numeric_uid_gid_on_unix() {
        let u = current_uid_gid().expect("id should be available on a unix test host");
        let (uid, gid) = u.split_once(':').expect("uid:gid format");
        assert!(!uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()));
        assert!(!gid.is_empty() && gid.bytes().all(|b| b.is_ascii_digit()));
    }
}
