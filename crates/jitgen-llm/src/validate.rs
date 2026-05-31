//! Static validation of generated candidate source (defense in depth; the F7 sandbox is the real
//! containment). Flags obviously-dangerous constructs before a candidate is ever executed.

use crate::util::char_prefix;

/// Hard cap on candidate bytes scanned, bounding the two lowercased/collapsed copies even if a very
/// large candidate reaches here (F5/S1 #5). Parsed candidates are already bounded upstream; this is
/// an independent defensive bound.
const MAX_VALIDATE_BYTES: usize = 512 * 1024;

/// Outcome of static validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// Whether the candidate is free of flagged dangerous constructs.
    pub ok: bool,
    /// Human-readable issues found (empty when `ok`).
    pub issues: Vec<String>,
}

/// (lowercased needle, reason) pairs for dangerous constructs. Network *clients* are not flagged
/// here because the sandbox blocks network anyway; we focus on destructive fs ops, process spawning,
/// and credential/sensitive-path access that signal a malicious or broken generated test.
const DANGEROUS: &[(&str, &str)] = &[
    ("rm -rf", "destructive shell command"),
    ("remove_dir_all", "recursive filesystem deletion"),
    ("shutil.rmtree", "recursive filesystem deletion"),
    (".rmsync", "recursive filesystem deletion"),
    ("os.system", "shell execution"),
    ("subprocess.", "process spawning"),
    ("child_process", "process spawning"),
    ("command::new", "process spawning"),
    ("processbuilder", "process spawning (java)"),
    ("getruntime", "Runtime.exec (java)"),
    (".popen", "process spawning (python)"),
    ("/etc/passwd", "sensitive file access"),
    ("/.ssh/", "ssh key access"),
    (".aws/credentials", "credential access"),
    ("import socket", "raw network access"),
    ("net.connect", "raw network access"),
];

/// Statically validate candidate source. Each needle is matched against both the lowercased source
/// and a whitespace-collapsed copy, so spacing tricks (`Command :: new`, `os . system`) cannot evade
/// the gate (F5/T1 review #6). This is a heuristic tripwire only — the F7 sandbox is the real
/// containment boundary; we never trust generated code merely because it passes here.
pub fn validate_candidate(source: &str) -> ValidationResult {
    let source = char_prefix(source, MAX_VALIDATE_BYTES);
    let lower = source.to_ascii_lowercase();
    let collapsed: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    let issues: Vec<String> = DANGEROUS
        .iter()
        .filter(|(needle, _)| lower.contains(needle) || collapsed.contains(needle))
        .map(|(needle, why)| format!("dangerous construct '{needle}' ({why})"))
        .collect();
    ValidationResult {
        ok: issues.is_empty(),
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_test_passes() {
        let r = validate_candidate("#[test]\nfn t() { assert_eq!(2, 1 + 1); }");
        assert!(r.ok, "{:?}", r.issues);
    }

    #[test]
    fn flags_destructive_and_exec() {
        assert!(!validate_candidate("std::fs::remove_dir_all(\"/\").unwrap();").ok);
        assert!(!validate_candidate("import os\nos.system('rm -rf /')").ok);
        assert!(!validate_candidate("std::process::Command::new(\"sh\")").ok);
    }

    #[test]
    fn flags_credential_access() {
        let r = validate_candidate("open('/home/u/.aws/credentials')");
        assert!(!r.ok);
        assert!(r.issues.iter().any(|i| i.contains("credential")));
    }

    #[test]
    fn flags_java_and_python_process_spawning() {
        assert!(!validate_candidate("new ProcessBuilder(\"sh\", \"-c\", \"id\").start();").ok);
        assert!(!validate_candidate("Runtime.getRuntime().exec(\"id\");").ok);
        assert!(!validate_candidate("import subprocess\nsubprocess.Popen(['id'])").ok);
    }

    #[test]
    fn whitespace_spacing_does_not_evade_the_gate() {
        // `Command :: new` and `os . system` would slip past a naive substring scan; the
        // whitespace-collapsed pass catches them (F5/T1 #6).
        assert!(!validate_candidate("std :: process :: Command :: new(\"sh\")").ok);
        assert!(!validate_candidate("os . system('rm -rf /')").ok);
    }
}
