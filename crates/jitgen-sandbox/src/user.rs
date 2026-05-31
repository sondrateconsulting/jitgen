//! Current `uid:gid` lookup for the container `--user` flag.
//!
//! Containers run as root by default; to keep an attacker-controlled test off root (and so writes to
//! the host-owned overlay bind mount carry the caller's ownership), the orchestrator runs the
//! container as the invoking user. `std` exposes no `getuid`/`getgid` without the `libc` crate, and
//! this crate is dependency-light and `#![forbid(unsafe_code)]`, so we read them from `id(1)` — the
//! same shell-out approach used by backend detection. Returns `None` off-unix or on any failure
//! (the caller then omits `--user`).

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
    let out = Command::new("id")
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
