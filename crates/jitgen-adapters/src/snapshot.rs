//! A read-only view of repository content at a revision, used for language detection and symbol
//! extraction. Built by the orchestrator from git **blobs** (never the working tree); tests build it
//! from in-memory maps.

use std::collections::{BTreeMap, BTreeSet};

/// Repo-relative head paths plus pre-read contents of selected files (manifests + changed sources).
#[derive(Debug, Default, Clone)]
pub struct RepoSnapshot {
    paths: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
}

impl RepoSnapshot {
    /// Build from a set of repo-relative paths and a map of pre-read file contents.
    pub fn new(
        paths: impl IntoIterator<Item = String>,
        files: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Self {
        let files: BTreeMap<String, Vec<u8>> = files.into_iter().collect();
        let mut path_set: BTreeSet<String> = paths.into_iter().collect();
        // Any file we have content for is necessarily present.
        path_set.extend(files.keys().cloned());
        Self {
            paths: path_set,
            files,
        }
    }

    /// Whether a path exists at the head revision.
    pub fn has(&self, path: &str) -> bool {
        self.paths.contains(path)
    }

    /// Whether any path has the given extension (no leading dot, e.g. `"ts"`).
    pub fn has_ext(&self, ext: &str) -> bool {
        let suffix = format!(".{ext}");
        self.paths.iter().any(|p| p.ends_with(&suffix))
    }

    /// Pre-read bytes for a path, if available.
    pub fn read(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(|v| v.as_slice())
    }

    /// Pre-read UTF-8 text for a path, if available and valid UTF-8.
    pub fn read_text(&self, path: &str) -> Option<&str> {
        self.read(path).and_then(|b| std::str::from_utf8(b).ok())
    }

    /// All known head paths.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.paths.iter().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_and_reads() {
        let snap = RepoSnapshot::new(
            ["src/a.rs".to_string(), "Cargo.toml".to_string()],
            [("Cargo.toml".to_string(), b"[package]\n".to_vec())],
        );
        assert!(snap.has("src/a.rs"));
        assert!(snap.has("Cargo.toml"));
        assert!(snap.has_ext("rs"));
        assert!(!snap.has_ext("py"));
        assert_eq!(snap.read_text("Cargo.toml"), Some("[package]\n"));
        assert_eq!(snap.read("missing"), None);
    }
}
