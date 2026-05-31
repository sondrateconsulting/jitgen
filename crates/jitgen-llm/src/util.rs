//! Small internal helpers shared across the crate.

/// Largest char-boundary prefix of `s` that is at most `max_bytes`. Used to bound work on
/// (potentially large, future-real-provider) model output before parsing/validating it (F5/S1 #5).
pub(crate) fn char_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_splits_utf8_and_respects_cap() {
        let s = "abc🌍def";
        for n in 0..=s.len() {
            let p = char_prefix(s, n);
            assert!(s.starts_with(p));
            assert!(p.len() <= n);
        }
    }

    #[test]
    fn returns_whole_string_when_under_cap() {
        assert_eq!(char_prefix("short", 100), "short");
    }
}
