//! Minimal glob matcher for `.jitgen.yaml` include/exclude patterns.
//!
//! Supports `?` (one non-`/` char), `*` (any run within a single path segment), and `**` (any run
//! of whole segments, including zero). Sufficient for common include/exclude forms; not a full
//! gitignore implementation.

/// Maximum accepted pattern length; over-long (untrusted) patterns never match (DoS bound; F4/S1 #2).
const MAX_GLOB_LEN: usize = 512;
/// Maximum accepted path length to match against.
const MAX_PATH_LEN: usize = 4096;

/// Whether `path` (forward-slash separated) matches the glob `pattern`.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    if pattern.len() > MAX_GLOB_LEN || path.len() > MAX_PATH_LEN {
        return false;
    }
    let pat: Vec<&str> = pattern.split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    match_segments(&pat, &segs)
}

/// Segment-level match where `**` is a wildcard over whole segments. Uses the same linear
/// two-pointer (single-star backtrack) algorithm as `segment_match`, so multiple `**` cannot cause
/// exponential state revisits (F4/T2 review #1) — it is O(pat_segments + path_segments).
fn match_segments(pat: &[&str], path: &[&str]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<usize> = None; // index in `pat` of the most recent `**`
    let mut mark = 0usize; // path position to backtrack to
    while si < path.len() {
        if pi < pat.len() && pat[pi] == "**" {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if pi < pat.len() && pat[pi] != "**" && segment_match(pat[pi], path[si]) {
            pi += 1;
            si += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == "**" {
        pi += 1;
    }
    pi == pat.len()
}

/// Single-segment match with `*`/`?` using the classic linear two-pointer algorithm — no recursion
/// and no exponential backtracking on adversarial patterns (F4/S1 #2).
fn segment_match(pat: &str, seg: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = seg.chars().collect();
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<usize> = None; // index in `p` of the last `*`
    let mut mark = 0usize; // position in `s` to backtrack to
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_common_patterns() {
        assert!(glob_match("*.go", "main.go"));
        assert!(!glob_match("*.go", "src/main.go")); // single-segment star
        assert!(glob_match("**/*.go", "src/a/main.go"));
        assert!(glob_match("**/*.go", "main.go")); // ** matches zero segments
        assert!(glob_match("src/**/*.ts", "src/a/b/c.ts"));
        assert!(glob_match("src/**/*.ts", "src/c.ts"));
        assert!(glob_match("src/?.rs", "src/a.rs"));
        assert!(!glob_match("src/?.rs", "src/ab.rs"));
        assert!(glob_match("vendor/**", "vendor/a/b"));
        assert!(!glob_match("test/**", "src/x"));
    }

    #[test]
    fn multiple_globstars_terminate_linearly() {
        // No exponential blowup / recursion (F4/T2 review #1).
        assert!(glob_match("**/**/x", "a/b/x"));
        assert!(glob_match("**/**/**/x", "x"));
        assert!(!glob_match("**/**/NOPE", "a/b/c/d/e"));
        // Over-long patterns never match (DoS cap).
        let long = "*".repeat(2000);
        assert!(!glob_match(&long, "anything"));
    }
}
