//! Per-output-format escaping, control/ANSI stripping, and length caps (security.md §10, threat #10).
//!
//! Every string that reaches a report originates from an **untrusted** source — a hostile repo's test
//! names, file paths, failure output, mutant descriptions, or an LLM's rationale. Even though the
//! producer (the orchestrator) already redacts secrets, the renderer must additionally guarantee that
//! untrusted content is rendered as **data, never markup or terminal controls**:
//!
//! 1. **Control/ANSI stripping** ([`sanitize`]): ESC (CSI/OSC/2-char) sequences, C0/C1 controls
//!    (except `\n`/`\t`), DEL, Unicode line/paragraph separators, and bidi/zero-width format chars are
//!    removed — so a test name can never move the cursor, recolor the terminal, or visually spoof.
//! 2. **Length caps** ([`cap`]): every field is bounded (DoS + log-flood control), UTF-8-safe.
//! 3. **Format-specific escaping**: Markdown/HTML ([`md_inline`]/[`md_code_block`]), XML for JUnit
//!    ([`xml_attr`]/[`xml_text`]), and JSON for SARIF (serde handles quoting; we only sanitize first).
//!
//! All public helpers sanitize internally, so callers cannot forget step 1.

/// Truncation marker appended when a value is capped. Shared across crates via `jitgen_core` so the
/// report, state, and context cap sites never drift to different suffixes.
const CAP_MARKER: &str = jitgen_core::TRUNCATION_MARKER;

/// Default caps (bytes) for the common field classes. Generous enough for real content, tight enough
/// to bound a hostile flood.
pub const CAP_NAME: usize = 512;
/// Cap for free-text fields (rationale, reasons, reproduction).
pub const CAP_TEXT: usize = 8 * 1024;
/// Cap for embedded source / multi-line output blocks.
pub const CAP_SOURCE: usize = 64 * 1024;

/// Remove ANSI escape sequences, C0/C1 control chars (except `\n` and `\t`), DEL, and Unicode
/// line/paragraph separators + bidi/zero-width format characters. The result is plain, inert text.
///
/// ESC handling is a small state machine: CSI (`ESC [`) is consumed through its final byte
/// (`0x40..=0x7E`); OSC (`ESC ]`) through `BEL` or `ST` (`ESC \`); any other `ESC x` drops both bytes.
/// A lone trailing `ESC` is dropped. This neutralizes the *control*, so residual parameter text (if
/// any) is already stripped as part of the sequence.
pub fn strip_controls(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1B}' => consume_escape(&mut chars), // ANSI/VT escape sequence
            '\u{9B}' => consume_csi_body(&mut chars), // C1 CSI introducer
            '\n' | '\t' => out.push(c),
            c if is_strippable(c) => {} // drop other controls / separators / format chars
            c => out.push(c),
        }
    }
    out
}

/// Whether `c` is a character we strip outright (outside the ESC/CSI machinery, and excluding the
/// `\n`/`\t` handled by the caller).
fn is_strippable(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{8}'        // C0 (minus \t \n handled separately)
        | '\u{B}' | '\u{C}'      // VT, FF
        | '\u{D}'                // CR — stripped so a bare \r can't reposition the cursor; CRLF collapses to LF
        | '\u{E}'..='\u{1F}'     // SO..US (ESC handled separately)
        | '\u{7F}'               // DEL
        | '\u{80}'..='\u{9F}'    // C1 controls
        | '\u{2028}' | '\u{2029}' // line / paragraph separators
        | '\u{200B}'..='\u{200F}' // zero-width + LRM/RLM
        | '\u{202A}'..='\u{202E}' // bidi embedding/override
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{FEFF}'             // BOM / ZWNBSP
    )
}

/// Consume the body of an ESC-introduced sequence (the `ESC` itself was already taken).
fn consume_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.peek() {
        Some('[') => {
            chars.next();
            consume_csi_body(chars);
        }
        Some(']') => {
            chars.next();
            consume_osc_body(chars);
        }
        Some(_) => {
            chars.next(); // a two-character escape: drop the following byte too
        }
        None => {} // lone trailing ESC
    }
}

/// Consume a CSI parameter/intermediate run through its final byte (`0x40..=0x7E`).
fn consume_csi_body(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    for c in chars.by_ref() {
        if ('\u{40}'..='\u{7E}').contains(&c) {
            break;
        }
    }
}

/// Consume an OSC string through `BEL` or the `ST` terminator (`ESC \`).
fn consume_osc_body(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next() {
        match c {
            '\u{7}' => break, // BEL
            '\u{1B}' => {
                if matches!(chars.peek(), Some('\\')) {
                    chars.next();
                }
                break;
            }
            _ => {}
        }
    }
}

/// Truncate `s` to at most `max` bytes on a UTF-8 char boundary, appending [`CAP_MARKER`] if cut.
/// When `max` is smaller than the marker, a char-boundary prefix of the marker is returned so the
/// result never exceeds `max`.
pub fn cap(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    if max < CAP_MARKER.len() {
        let mut end = max;
        while end > 0 && !CAP_MARKER.is_char_boundary(end) {
            end -= 1;
        }
        return CAP_MARKER[..end].to_string();
    }
    let mut end = max - CAP_MARKER.len();
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{CAP_MARKER}", &s[..end])
}

/// Strip controls then cap — the inert plain-text base every format escaper builds on.
pub fn sanitize(s: &str, max: usize) -> String {
    cap(&strip_controls(s), max)
}

/// Strip controls + cap, then flatten the intentionally-kept `\n`/`\t` to spaces — the inert,
/// guaranteed **single-line** form for a terminal field or a one-line report cell (a path, a
/// rationale, a warning). `sanitize` already removes CR/ANSI/C0-C1/DEL/bidi; this additionally stops a
/// hostile value from forging an extra line or column (e.g. a path containing `\nsummary: 0 rejected`
/// faking a report row). Use `sanitize` (not this) for legitimately multi-line bodies — patch/source
/// blocks, fenced code, XML `<failure>` text (security review F1).
pub fn sanitize_line(s: &str, max: usize) -> String {
    sanitize(s, max).replace(['\n', '\t'], " ")
}

/// Escape a single-line untrusted value for **Markdown/HTML inline** context (a table cell, a list
/// item, a bolded label value). Newlines collapse to spaces; CommonMark + HTML metacharacters are
/// backslash/entity-escaped so the value can never form a heading, link, emphasis, code span, table
/// pipe, or HTML tag.
pub fn md_inline(s: &str, max: usize) -> String {
    let base = sanitize(s, max);
    let mut out = String::with_capacity(base.len() + 8);
    for c in base.chars() {
        match c {
            '\n' | '\r' => out.push(' '),
            // HTML-significant: entity-encode so `<script>`/`&` cannot inject markup.
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            // CommonMark-significant punctuation: backslash-escape.
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '.'
            | '!' | '|' | '~' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// Sanitize untrusted multi-line content for embedding **inside a fenced Markdown code block**.
/// Backtick runs of length >= 3 (which could close the fence) are neutralized; controls are stripped;
/// length is capped. The caller wraps the result in a fence (this crate uses a `~~~` fence, which a
/// backtick run cannot close, as belt-and-suspenders).
pub fn md_code_block(s: &str, max: usize) -> String {
    let base = sanitize(s, max);
    // Neutralize any run of 3+ backticks AND any tilde run (we fence with `~~~`).
    let mut out = String::with_capacity(base.len());
    let mut backticks = 0usize;
    let mut tildes = 0usize;
    let flush = |out: &mut String, n: &mut usize, ch: char| {
        if *n >= 3 {
            // Break the run so it cannot terminate either fence style.
            for _ in 0..*n {
                out.push(ch);
                out.push('\u{200B}'); // stripped on a later re-sanitize, but inert here
            }
        } else {
            for _ in 0..*n {
                out.push(ch);
            }
        }
        *n = 0;
    };
    for c in base.chars() {
        match c {
            '`' => {
                flush(&mut out, &mut tildes, '~');
                backticks += 1;
            }
            '~' => {
                flush(&mut out, &mut backticks, '`');
                tildes += 1;
            }
            other => {
                flush(&mut out, &mut backticks, '`');
                flush(&mut out, &mut tildes, '~');
                out.push(other);
            }
        }
    }
    flush(&mut out, &mut backticks, '`');
    flush(&mut out, &mut tildes, '~');
    out
}

/// Escape an untrusted value for an **XML attribute** (JUnit `name`/`classname`/`message`). Newlines
/// and tabs collapse to spaces (attributes are single-line); `& < > " '` are entity-encoded. Controls
/// were already stripped, satisfying XML 1.0's character rules.
pub fn xml_attr(s: &str, max: usize) -> String {
    let base = sanitize(s, max);
    let mut out = String::with_capacity(base.len() + 8);
    for c in base.chars() {
        match c {
            '\n' | '\t' | '\r' => out.push(' '),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Escape an untrusted value for **XML text content** (a JUnit `<failure>` body). Newlines are kept;
/// `& < >` are entity-encoded so the content cannot close the element or inject a sibling tag.
pub fn xml_text(s: &str, max: usize) -> String {
    let base = sanitize(s, max);
    let mut out = String::with_capacity(base.len() + 8);
    for c in base.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_csi_color_sequences() {
        // A red "PWNED" with cursor moves must become inert text with no ESC bytes.
        let evil = "\u{1B}[31mPWNED\u{1B}[0m\u{1B}[2J\u{1B}[1;1H";
        let clean = strip_controls(evil);
        assert!(!clean.contains('\u{1B}'), "ESC survived: {clean:?}");
        assert!(!clean.contains("[31m"), "CSI body survived: {clean:?}");
        assert_eq!(clean, "PWNED");
    }

    #[test]
    fn strips_osc_hyperlink_and_title_sequences() {
        // OSC 8 hyperlink + OSC 0 window-title injection.
        let evil = "\u{1B}]8;;http://evil\u{7}click\u{1B}]0;owned\u{1B}\\done";
        let clean = strip_controls(evil);
        assert!(!clean.contains('\u{1B}'));
        assert_eq!(clean, "clickdone");
    }

    #[test]
    fn strips_c1_csi_and_bare_controls_keeps_tab_newline() {
        let s = "a\u{9B}31mb\u{0}\u{7}c\nd\te\u{7F}f";
        let clean = strip_controls(s);
        assert_eq!(clean, "abc\nd\tef");
    }

    #[test]
    fn strips_carriage_return_so_crlf_collapses_to_lf() {
        // CR (U+000D) is a terminal-spoofing primitive — a bare `\r` returns the cursor to column 0
        // and overwrites the current line. It is NOT in the `\n`/`\t` keep-set, so it must be stripped:
        // a CRLF collapses to a clean LF and a lone CR vanishes (security review F1 follow-up).
        assert_eq!(strip_controls("line1\r\nline2"), "line1\nline2");
        assert_eq!(
            strip_controls("real error\roverwrite"),
            "real erroroverwrite"
        );
        assert!(!strip_controls("x\r\ny").contains('\r'));
    }

    #[test]
    fn sanitize_line_flattens_to_a_single_inert_line() {
        // A hostile single-line field must not forge an extra line/column or carry any control.
        let evil = "tests/x\n  + /fake/pwn.rs [rust]\r\tcol\u{1b}[31m";
        let out = sanitize_line(evil, CAP_NAME);
        assert!(!out.contains('\n'), "LF survived: {out:?}");
        assert!(!out.contains('\r'), "CR survived: {out:?}");
        assert!(!out.contains('\t'), "tab survived: {out:?}");
        assert!(!out.contains('\u{1b}'), "ESC survived: {out:?}");
        assert!(out.starts_with("tests/x"), "content dropped: {out:?}");
    }

    #[test]
    fn strips_bidi_and_zero_width_spoofing() {
        // Right-to-left override + zero-width space used to visually spoof a filename.
        let s = "safe\u{202E}txt.exe\u{200B}\u{FEFF}end";
        let clean = strip_controls(s);
        assert!(!clean.contains('\u{202E}'));
        assert!(!clean.contains('\u{200B}'));
        assert!(!clean.contains('\u{FEFF}'));
        assert_eq!(clean, "safetxt.exeend");
    }

    #[test]
    fn cap_is_utf8_safe_and_never_exceeds() {
        let s = "héllo wörld 🌍 ".repeat(100);
        for max in 0..40 {
            let out = cap(&s, max);
            assert!(out.len() <= max, "max={max} len={}", out.len());
            assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        }
    }

    #[test]
    fn cap_appends_shared_marker_and_respects_max_around_marker_length() {
        // A clearly-over-cap value ends with the shared marker and never exceeds `max`. Exercises the
        // boundary straddling the marker's own byte length (the marker is multi-byte: `…` + text), so a
        // longer/shorter shared marker can never make `cap` exceed `max` or split a UTF-8 boundary.
        let long = "x".repeat(100);
        let marker_len = jitgen_core::TRUNCATION_MARKER.len();
        let ample = cap(&long, marker_len + 26);
        assert!(ample.ends_with(jitgen_core::TRUNCATION_MARKER), "{ample}");
        assert!(ample.len() <= marker_len + 26);
        for max in marker_len.saturating_sub(4)..=(marker_len + 1) {
            let out = cap(&long, max);
            assert!(out.len() <= max, "max={max} len={}", out.len());
            assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        }
    }

    #[test]
    fn md_inline_neutralizes_markdown_and_html_injection() {
        // A test name attempting a heading, a link, emphasis, a table break, and an HTML tag.
        let evil = "# H [x](http://e) *b* `c` |col| <img src=x onerror=alert(1)>";
        let out = md_inline(evil, CAP_TEXT);
        // Markdown-significant punctuation is backslash-escaped (rendered as literal data, not markup):
        // each metacharacter is immediately preceded by a backslash.
        assert!(out.contains("\\# H"), "{out}");
        assert!(out.contains("\\[x\\]\\(http://e\\)"), "{out}");
        assert!(out.contains("\\*b\\*"), "{out}");
        assert!(out.contains("\\`c\\`"), "{out}");
        assert!(out.contains("\\|col\\|"), "{out}");
        // HTML is entity-encoded, never a live tag.
        assert!(!out.contains("<img"), "{out}");
        assert!(out.contains("&lt;img"), "{out}");
        // Newlines collapse so a value cannot start a new markdown block.
        assert!(!md_inline("line1\nline2", CAP_TEXT).contains('\n'));
    }

    #[test]
    fn md_code_block_neutralizes_fence_breakout() {
        // Source attempting to close a ``` fence and inject a heading after it.
        let evil = "ok();\n```\n# INJECTED HEADING\n```js\nalert(1)";
        let out = md_code_block(evil, CAP_SOURCE);
        assert!(
            !out.contains("```"),
            "triple-backtick fence survived: {out:?}"
        );
        // The benign code text is preserved (minus the dangerous fence run).
        assert!(out.contains("INJECTED HEADING")); // now inert inside the fence
    }

    #[test]
    fn xml_attr_escapes_and_single_lines() {
        let evil = "name\"/><testcase name=\"evil\nsecond";
        let out = xml_attr(evil, CAP_NAME);
        assert!(!out.contains('<'), "{out}");
        assert!(!out.contains('"'), "{out}");
        assert!(out.contains("&quot;") && out.contains("&lt;"));
        assert!(!out.contains('\n'), "attribute must be single line: {out}");
    }

    #[test]
    fn xml_text_escapes_closing_tags() {
        let evil = "boom</failure><testcase/><![CDATA[x]]>";
        let out = xml_text(evil, CAP_TEXT);
        assert!(!out.contains("</failure>"), "{out}");
        assert!(out.contains("&lt;/failure&gt;"));
    }

    #[test]
    fn sanitize_strips_then_caps() {
        let s = format!("\u{1B}[31m{}", "x".repeat(100));
        let out = sanitize(&s, 10);
        assert!(!out.contains('\u{1B}'));
        assert!(out.len() <= 10);
    }
}
