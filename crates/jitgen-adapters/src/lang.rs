//! Language identity: file-extension mapping, tree-sitter grammar selection, and the per-language
//! set of "interesting" declaration node kinds → [`SymbolKind`] (ADR-0007).

use jitgen_core::SymbolKind;
use tree_sitter::Language;

/// A source language jitgen can extract symbols from with a compiled-in tree-sitter grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Rust,
    Python,
    Java,
    TypeScript,
    Tsx,
}

impl Lang {
    /// Map a repo-relative path to a language by extension (`None` if unknown).
    pub fn from_path(path: &str) -> Option<Lang> {
        let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        match ext.as_str() {
            "rs" => Some(Lang::Rust),
            "py" | "pyi" => Some(Lang::Python),
            "java" => Some(Lang::Java),
            "ts" | "mts" | "cts" => Some(Lang::TypeScript),
            // JSX/TSX require the TSX grammar variant.
            "tsx" | "jsx" => Some(Lang::Tsx),
            // The TypeScript grammar is a superset that parses plain JS reasonably.
            "js" | "mjs" | "cjs" => Some(Lang::TypeScript),
            _ => None,
        }
    }

    /// The compiled-in tree-sitter grammar for this language.
    pub fn ts_language(self) -> Language {
        match self {
            Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
            Lang::Python => tree_sitter_python::LANGUAGE.into(),
            Lang::Java => tree_sitter_java::LANGUAGE.into(),
            Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        }
    }

    /// Tree-sitter node kinds that denote a named code unit, paired with our [`SymbolKind`].
    pub fn symbol_kinds(self) -> &'static [(&'static str, SymbolKind)] {
        match self {
            Lang::Rust => &[
                ("function_item", SymbolKind::Function),
                ("struct_item", SymbolKind::Class),
                ("enum_item", SymbolKind::Class),
                ("trait_item", SymbolKind::Class),
                ("impl_item", SymbolKind::Class),
                ("mod_item", SymbolKind::Module),
            ],
            Lang::Python => &[
                ("function_definition", SymbolKind::Function),
                ("class_definition", SymbolKind::Class),
            ],
            Lang::Java => &[
                ("method_declaration", SymbolKind::Method),
                ("constructor_declaration", SymbolKind::Method),
                ("class_declaration", SymbolKind::Class),
                ("interface_declaration", SymbolKind::Class),
                ("enum_declaration", SymbolKind::Class),
            ],
            Lang::TypeScript | Lang::Tsx => &[
                ("function_declaration", SymbolKind::Function),
                ("method_definition", SymbolKind::Method),
                ("class_declaration", SymbolKind::Class),
                ("abstract_class_declaration", SymbolKind::Class),
                ("interface_declaration", SymbolKind::Class),
                // `const f = () => {}` / `const f = function() {}` (name recovered from the parent
                // declarator by `symbols::node_name`).
                ("arrow_function", SymbolKind::Function),
                ("function_expression", SymbolKind::Function),
                ("generator_function", SymbolKind::Function),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_mapping() {
        assert_eq!(Lang::from_path("src/a.rs"), Some(Lang::Rust));
        assert_eq!(Lang::from_path("m/a.py"), Some(Lang::Python));
        assert_eq!(Lang::from_path("A.java"), Some(Lang::Java));
        assert_eq!(Lang::from_path("c.ts"), Some(Lang::TypeScript));
        assert_eq!(Lang::from_path("c.tsx"), Some(Lang::Tsx));
        assert_eq!(Lang::from_path("README.md"), None);
    }

    #[test]
    fn grammars_load() {
        // Each compiled-in grammar is usable (no ABI mismatch).
        for lang in [
            Lang::Rust,
            Lang::Python,
            Lang::Java,
            Lang::TypeScript,
            Lang::Tsx,
        ] {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&lang.ts_language())
                .unwrap_or_else(|e| panic!("set_language {lang:?}: {e}"));
        }
    }
}
