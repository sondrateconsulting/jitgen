//! Per-language test-file placement conventions.
//!
//! Given a [`Target`] and its adapter id, derive a conventional **overlay-relative** path for the
//! generated test. This is a pure, deterministic helper used by the orchestrator to set a
//! [`jitgen_core::TestCandidate::rel_path`] when the model did not supply a sound one. All
//! interpolated, repo-derived fragments (file stems, symbol names, target ids) are sanitized to a
//! conservative identifier charset, so a hostile symbol/path can never inject a separator, traversal,
//! or extension. The returned path is always relative, separator-clean, and confined under the
//! overlay once written (the materializer re-validates).

use jitgen_core::Target;
use std::path::{Component, Path};

/// Maximum length of a sanitized fragment used in a derived filename.
const MAX_FRAGMENT: usize = 64;

/// Reduce an arbitrary repo-derived string to `[A-Za-z0-9_]`, collapse repeats, and length-cap so it
/// is always a safe single path-segment fragment. Empty input yields `unit`.
fn sanitize_fragment(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_FRAGMENT));
    let mut last_us = false;
    for ch in s.chars() {
        let c = if ch.is_ascii_alphanumeric() { ch } else { '_' };
        if c == '_' {
            if last_us {
                continue;
            }
            last_us = true;
        } else {
            last_us = false;
        }
        out.push(c);
        if out.len() >= MAX_FRAGMENT {
            break;
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "unit".to_string()
    } else {
        trimmed.to_string()
    }
}

/// First-uppercase a fragment (for Java class names): `foo_bar` -> `FooBar` is not attempted; we only
/// capitalize the first character to keep the source stem recognizable.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// The directory portion of a repo-relative path as a POSIX-joined string of **Normal components
/// only** — root/`.`/`..`/drive-prefix components are dropped, so the result is always relative and
/// traversal-free regardless of the input (defense-in-depth; the materializer re-validates anyway).
/// Components are emitted verbatim (no `\`→`/` rewrite — that previously turned a single Normal
/// component like `a\..` into the two-component `a/..`, reintroducing traversal: F6/T1 #2). Repo paths
/// from intake are already `/`-separated and `\`-free.
fn dir_of(path: &str) -> String {
    let parent = match Path::new(path).parent() {
        Some(p) => p,
        None => return String::new(),
    };
    parent
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The file stem of a repo-relative path (sanitized), or `unit`.
fn stem_of(path: &str) -> String {
    let stem = Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    sanitize_fragment(&stem)
}

/// A short, sanitized disambiguator derived from the target id.
fn short_id(target: &Target) -> String {
    sanitize_fragment(&target.id.to_string())
}

/// Derive a conventional overlay-relative test path for `target` under `adapter_id`.
pub fn test_path(target: &Target, adapter_id: &str) -> String {
    let stem = stem_of(&target.path);
    let id = short_id(target);
    let dir = dir_of(&target.path);
    let with_dir = |name: String| -> String {
        if dir.is_empty() {
            name
        } else {
            format!("{dir}/{name}")
        }
    };

    match adapter_id {
        // Integration test in `tests/` (no source mutation; exercises the public API).
        "rust" => format!("tests/jitgen_{stem}_{id}.rs"),
        // pytest discovers `test_*.py`; place beside the module so relative imports resolve. The id
        // keeps two targets in one module from colliding (F6/S1 #1).
        "python" => with_dir(format!("test_{stem}_jitgen_{id}.py")),
        // Maven/Gradle: mirror `src/main/...` under `src/test/java` with a `*Test` class.
        "java" => java_test_path(&target.path, &stem, &id),
        // Jest/Vitest: `*.test.<ext>` beside the source, id-disambiguated (F6/S1 #1). The source
        // extension family is preserved (F6/T2 #3) so a `.tsx`/`.js`/`.mjs` source gets a matching
        // test extension (JSX parse mode / JS-only projects).
        "typescript" => with_dir(format!(
            "{stem}.jitgen.{id}.test.{}",
            ts_test_ext(&target.path)
        )),
        // Generic/unknown: a dedicated, clearly-namespaced directory.
        _ => format!("jitgen-tests/{stem}_{id}.test.txt"),
    }
}

/// The JavaScript/TypeScript test-file extension to use for a source path, preserving the source's
/// extension family (F6/T2 #3). F4's TypeScript adapter owns `ts/tsx/js/jsx/mjs/cjs/mts/cts`; an
/// unknown/missing extension defaults to `ts`.
fn ts_test_ext(src_path: &str) -> &'static str {
    let ext = Path::new(src_path)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "tsx" => "tsx",
        "js" => "js",
        "jsx" => "jsx",
        "mjs" => "mjs",
        "cjs" => "cjs",
        "mts" => "mts",
        "cts" => "cts",
        _ => "ts",
    }
}

/// Java placement: if the source lives under a `src/main/java/<pkg>/` segment, replace `main` with
/// `test` **in place** — preserving any module prefix before it (e.g. `module-a/`) and the package
/// dirs after it — and name the class `<Stem>Jitgen<Id>Test.java`. The disambiguator sits **before**
/// the `Test` suffix so the class still matches Maven Surefire / Gradle default discovery patterns
/// (`*Test`) and actually runs (F6/T2 #2), while staying a unique, valid Java identifier when several
/// targets share one source file (F6/T1 #3). If the standard layout is absent, fall back to a flat
/// `src/test/java/<Class>.java`.
fn java_test_path(src_path: &str, stem: &str, id: &str) -> String {
    let class = format!("{}Jitgen{}Test", capitalize(stem), capitalize(id));
    let comps: Vec<String> = Path::new(src_path)
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    // Need at least `src/main/java/<file>` (4 components) to mirror; the last component is the file.
    if comps.len() >= 4 {
        let file_idx = comps.len() - 1;
        for i in 0..=comps.len() - 3 {
            if comps[i] == "src" && comps[i + 1] == "main" && comps[i + 2] == "java" {
                let mut out: Vec<String> = comps[..i].to_vec();
                out.extend(["src".to_string(), "test".to_string(), "java".to_string()]);
                // Package dirs sit between `java` and the filename.
                if let Some(pkg) = comps.get(i + 3..file_idx) {
                    out.extend(pkg.iter().cloned());
                }
                out.push(format!("{class}.java"));
                return out.join("/");
            }
        }
    }
    format!("src/test/java/{class}.java")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{AdapterId, LineRange, RiskScore, SymbolKind, TargetId};

    fn target(path: &str, symbol: Option<&str>, adapter: &str) -> Target {
        Target {
            id: TargetId::new("t7"),
            adapter: AdapterId::new(adapter),
            path: path.to_string(),
            symbol: symbol.map(|s| s.to_string()),
            kind: SymbolKind::Function,
            span: LineRange::new(1, 3).unwrap(),
            risk: RiskScore::new(0.5).unwrap(),
        }
    }

    #[test]
    fn rust_goes_to_tests_dir() {
        let p = test_path(&target("src/math/add.rs", Some("add"), "rust"), "rust");
        assert_eq!(p, "tests/jitgen_add_t7.rs");
    }

    #[test]
    fn python_is_beside_module_and_id_disambiguated() {
        let p = test_path(&target("pkg/calc.py", None, "python"), "python");
        assert_eq!(p, "pkg/test_calc_jitgen_t7.py");
    }

    #[test]
    fn typescript_is_beside_source_and_id_disambiguated() {
        let p = test_path(
            &target("src/widgets/button.ts", None, "typescript"),
            "typescript",
        );
        assert_eq!(p, "src/widgets/button.jitgen.t7.test.ts");
    }

    #[test]
    fn typescript_preserves_source_extension_family() {
        // F6/T2 #3: tsx/js/jsx/mjs sources keep their family in the test extension.
        for (src, ext) in [
            ("src/a.tsx", "tsx"),
            ("src/a.js", "js"),
            ("src/a.jsx", "jsx"),
            ("src/a.mjs", "mjs"),
            ("src/a.cts", "cts"),
            ("src/a.weird", "ts"), // unknown → default ts
        ] {
            let p = test_path(&target(src, None, "typescript"), "typescript");
            assert!(p.ends_with(&format!(".test.{ext}")), "{src} -> {p}");
        }
    }

    #[test]
    fn distinct_targets_in_one_source_do_not_collide() {
        // F6/S1 #1: two targets in the same .py/.ts file get distinct paths.
        let mut a = target("pkg/calc.py", None, "python");
        let mut b = a.clone();
        a.id = TargetId::new("t1");
        b.id = TargetId::new("t2");
        assert_ne!(test_path(&a, "python"), test_path(&b, "python"));
        let mut c = target("src/foo.ts", None, "typescript");
        let mut d = c.clone();
        c.id = TargetId::new("t1");
        d.id = TargetId::new("t2");
        assert_ne!(test_path(&c, "typescript"), test_path(&d, "typescript"));
    }

    #[test]
    fn java_mirrors_into_src_test_java() {
        let p = test_path(
            &target("src/main/java/com/x/Foo.java", None, "java"),
            "java",
        );
        assert_eq!(p, "src/test/java/com/x/FooJitgenT7Test.java");
    }

    #[test]
    fn java_without_standard_layout_falls_back() {
        let p = test_path(&target("Foo.java", None, "java"), "java");
        assert_eq!(p, "src/test/java/FooJitgenT7Test.java");
    }

    #[test]
    fn java_preserves_module_prefix() {
        // F6/T1 #3: a module prefix before `src/main/java` must be preserved, not dropped.
        let p = test_path(
            &target("module-a/src/main/java/com/x/Foo.java", None, "java"),
            "java",
        );
        assert_eq!(p, "module-a/src/test/java/com/x/FooJitgenT7Test.java");
    }

    #[test]
    fn java_no_package_directly_under_java() {
        let p = test_path(&target("src/main/java/Foo.java", None, "java"), "java");
        assert_eq!(p, "src/test/java/FooJitgenT7Test.java");
    }

    #[test]
    fn derived_paths_never_contain_parent_dir_component() {
        // F6/T1 #2: no input (incl. backslash-bearing names) yields a `..` path component.
        for (path, adapter) in [
            ("a/b/../c.py", "python"),
            ("weird\\name/mod.rs", "rust"),
            ("x/y\\..\\z.ts", "typescript"),
        ] {
            let p = test_path(&target(path, None, adapter), adapter);
            let has_parent = std::path::Path::new(&p)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir));
            assert!(!has_parent, "{path} ({adapter}) -> {p}");
            assert!(!p.starts_with('/'), "{p}");
        }
    }

    #[test]
    fn generic_uses_namespaced_dir() {
        let p = test_path(&target("weird/thing.xyz", None, "acme-lang"), "acme-lang");
        assert_eq!(p, "jitgen-tests/thing_t7.test.txt");
    }

    #[test]
    fn hostile_symbol_and_path_are_sanitized() {
        // A path whose stem carries separators/specials cannot inject path structure.
        let p = test_path(&target("a/b/../e!vil name.py", None, "python"), "python");
        // dir keeps only Normal components; the stem is sanitized to a single safe segment.
        assert!(!p.contains(".."), "{p}");
        assert!(p.ends_with(".py"), "{p}");
        assert!(p.starts_with("test_") || p.contains("/test_"), "{p}");
    }

    #[test]
    fn empty_stem_becomes_unit() {
        let p = test_path(&target("src/.gitignore", None, "rust"), "rust");
        assert_eq!(p, "tests/jitgen_gitignore_t7.rs");
    }
}
