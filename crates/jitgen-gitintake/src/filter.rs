//! Path classification: which repo paths to exclude from test generation.
//!
//! Vendored/build-output directories are never targets; secret-bearing files are excluded entirely
//! so their contents can never enter the diff, context, or prompts (security §3).

/// Path segments that are vendored dependencies or build output.
const VENDOR_SEGMENTS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".gradle",
    "coverage",
    ".idea",
    ".vscode",
    "bazel-bin",
    "bazel-out",
    "bazel-testlogs",
];

/// Exact file names that may carry secrets (`_netrc` is git-for-Windows' `.netrc`).
const SECRET_NAMES: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".pgpass",
];

/// File-name prefixes that may carry secrets (covers `id_rsa`, `id_rsa.old`, `credentials.json`, …).
const SECRET_PREFIXES: &[&str] = &["id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", "credentials"];

/// File-name suffixes that may carry secrets/keys.
const SECRET_SUFFIXES: &[&str] = &[
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".keystore",
    ".jks",
    ".ppk",
    ".gpg",
];

/// Whether `path` (repo-relative, forward-slash) should be ignored for test generation.
pub fn is_ignored(path: &str) -> bool {
    is_vendored(path) || is_secret_like(path)
}

/// Whether any path segment is a vendored/build-output directory. ASCII case-insensitive
/// (`Node_Modules`, `TARGET`, … are still caught — F3/S1 review #2).
pub fn is_vendored(path: &str) -> bool {
    path.split('/')
        .any(|seg| VENDOR_SEGMENTS.contains(&seg.to_ascii_lowercase().as_str()))
}

/// Whether the file name (or path) looks secret-bearing (excluded from context entirely). ASCII
/// case-insensitive so `.ENV`, `ID_RSA.old`, `Server.PEM`, … are still caught.
pub fn is_secret_like(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // Path-level: package-manager credential stores (e.g. `.cargo/credentials.toml`).
    if lower.contains(".cargo/credentials") || lower.contains(".aws/credentials") {
        return true;
    }
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if SECRET_NAMES.contains(&name) {
        return true;
    }
    // `.env`, `.env.local`, `.env.production`, …
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    if SECRET_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    SECRET_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_paths_are_ignored() {
        assert!(is_ignored("node_modules/left-pad/index.js"));
        assert!(is_ignored("target/debug/foo"));
        assert!(is_ignored("a/b/dist/bundle.js"));
        assert!(is_ignored(".git/config"));
        assert!(!is_ignored("src/lib.rs"));
        assert!(!is_ignored("packages/app/src/main.ts"));
    }

    #[test]
    fn secret_files_are_ignored() {
        assert!(is_ignored(".env"));
        assert!(is_ignored("config/.env.production"));
        assert!(is_ignored("keys/server.pem"));
        assert!(is_ignored("deploy/id_rsa"));
        assert!(is_ignored("app/.npmrc"));
        // Glob-style credential patterns (F3/T1 review #2).
        assert!(is_ignored("deploy/id_rsa.old"));
        assert!(is_ignored("auth/credentials.json"));
        assert!(is_ignored("home/.cargo/credentials.toml"));
        assert!(is_ignored("home/.aws/credentials"));
        // git's plaintext credential store (`https://user:token@host` lines).
        assert!(is_ignored(".git-credentials"));
        assert!(is_ignored("home/.git-credentials"));
        // Same-class plaintext stores: Windows .netrc, PostgreSQL password file.
        assert!(is_ignored("_netrc"));
        assert!(is_ignored("home/_netrc"));
        assert!(is_ignored(".pgpass"));
        assert!(is_ignored("home/.pgpass"));
        // Key-store/key-file suffixes.
        assert!(is_ignored("ci/release.jks"));
        assert!(is_ignored("deploy/server.ppk"));
        assert!(is_ignored("secrets/api-token.gpg"));
        assert!(!is_ignored("src/environment.ts"));
        assert!(!is_ignored("src/credential_helper.rs")); // not a credential store
        assert!(!is_ignored("docs/git-credentials.md")); // name, not the store itself
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(is_ignored("Node_Modules/pkg/index.js"));
        assert!(is_ignored("TARGET/debug/x"));
        assert!(is_ignored(".ENV"));
        assert!(is_ignored("keys/Server.PEM"));
        assert!(is_ignored("deploy/ID_RSA.old"));
        assert!(is_ignored("home/.GIT-CREDENTIALS"));
        assert!(is_ignored("home/_NETRC"));
        assert!(is_ignored("ci/release.JKS"));
        assert!(is_ignored("deploy/server.PPK"));
        assert!(is_ignored("secrets/api-token.GPG"));
    }
}
