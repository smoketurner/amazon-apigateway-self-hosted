//! Java's case-insensitive comparison under `UNICODE_CASE`.
//!
//! Java does not case-fold. It compares through `Character.toUpperCase` and
//! `Character.toLowerCase`, the simple one-to-one mappings, and does so differently for a lone
//! literal, a run of literals, a character in a class, and a class range. That is why, for
//! example, `(?iu)i` matches `İ` and `ı` while Unicode case folding does not. This module
//! computes, at translation time, the exact set of characters each of those matches.

use std::sync::OnceLock;

/// A character with a case mapping, its simple upper case, and `lower(upper(c))`.
#[derive(Debug, Clone, Copy)]
struct Cased {
    ch: char,
    upper: char,
    folded: char,
}

/// Java's simple case mappings for one character.
#[derive(Debug)]
pub(crate) struct JavaCase;

impl JavaCase {
    /// `Character.toUpperCase`.
    ///
    /// Rust's mapping is the full one; where that is several characters, the simple mapping
    /// from `UnicodeData.txt` is the character itself except for the Greek letters with
    /// ypogegrammeni, whose simple upper case is the titlecase form.
    pub(crate) fn upper(c: char) -> char {
        let mut mapped = c.to_uppercase();
        match (mapped.next(), mapped.next()) {
            (Some(single), None) => single,
            _ => match u32::from(c) {
                0x1F80..=0x1F87 | 0x1F90..=0x1F97 | 0x1FA0..=0x1FA7 => {
                    char::from_u32(u32::from(c).saturating_add(8)).unwrap_or(c)
                }
                0x1FB3 => '\u{1FBC}',
                0x1FC3 => '\u{1FCC}',
                0x1FF3 => '\u{1FFC}',
                _ => c,
            },
        }
    }

    /// `Character.toLowerCase`; only `İ` has a multi-character full mapping.
    pub(crate) fn lower(c: char) -> char {
        let mut mapped = c.to_lowercase();
        match (mapped.next(), mapped.next()) {
            (Some(single), None) => single,
            _ if c == '\u{130}' => 'i',
            _ => c,
        }
    }

    /// `toLowerCase(toUpperCase(c))`, the value Java compares.
    pub(crate) fn fold(c: char) -> char {
        Self::lower(Self::upper(c))
    }

    /// Every character that has a case mapping, computed once.
    fn cased() -> &'static [Cased] {
        static CASED: OnceLock<Vec<Cased>> = OnceLock::new();
        CASED.get_or_init(|| {
            let mut cased = Vec::new();
            for ch in '\0'..=char::MAX {
                let upper = Self::upper(ch);
                if upper != ch || Self::lower(ch) != ch {
                    cased.push(Cased {
                        ch,
                        upper,
                        folded: Self::lower(upper),
                    });
                }
            }
            cased
        })
    }

    /// The characters a lone literal `c` matches (`Pattern.single`, `SingleU`).
    pub(crate) fn single(c: char) -> Vec<char> {
        let upper = Self::upper(c);
        let lower = Self::lower(upper);
        if upper == lower {
            return vec![c];
        }
        Self::with_fold(lower)
    }

    /// The characters `c` matches inside a run of literals (`SliceU`).
    pub(crate) fn in_slice(c: char) -> Vec<char> {
        Self::with_fold(Self::fold(c))
    }

    /// `lower` itself and every character that folds to it.
    fn with_fold(lower: char) -> Vec<char> {
        let mut chars = vec![lower];
        for entry in Self::cased() {
            if entry.folded == lower && entry.ch != lower {
                chars.push(entry.ch);
            }
        }
        chars
    }

    /// The characters a single character `c` matches inside a class.
    ///
    /// Java keeps characters below U+0100 in a bit set together with their simple upper and
    /// lower case, except for the few whose case partners lie outside Latin-1, which go through
    /// [`JavaCase::single`] (`Pattern.bitsOrSingle`).
    pub(crate) fn in_class(c: char) -> Vec<char> {
        let special = matches!(
            c,
            '\u{FF}' | '\u{B5}' | 'I' | 'i' | 'S' | 's' | 'K' | 'k' | '\u{C5}' | '\u{E5}'
        );
        if u32::from(c) < 0x100 && !special {
            let mut chars = vec![c, Self::lower(c), Self::upper(c)];
            chars.sort_unstable();
            chars.dedup();
            return chars;
        }
        Self::single(c)
    }

    /// The characters outside `low..=high` that the range matches case-insensitively: those
    /// whose upper case, or the lower case of that, is in the range (`Pattern.CIRangeU`).
    pub(crate) fn range_extras(low: char, high: char) -> Vec<char> {
        let inside = |c: char| low <= c && c <= high;
        Self::cased()
            .iter()
            .filter(|entry| !inside(entry.ch) && (inside(entry.upper) || inside(entry.folded)))
            .map(|entry| entry.ch)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_and_dotless_i_compare_equal_to_i() {
        let mut chars = JavaCase::single('i');
        chars.sort_unstable();
        assert_eq!(chars, ['I', 'i', '\u{130}', '\u{131}']);
        assert_eq!(JavaCase::single('\u{131}'), JavaCase::single('i'));
    }

    #[test]
    fn a_lone_sharp_s_is_exact_but_folds_in_a_run() {
        assert_eq!(JavaCase::single('ß'), ['ß']);
        let mut chars = JavaCase::in_slice('ß');
        chars.sort_unstable();
        assert_eq!(chars, ['ß', '\u{1E9E}']);
    }

    #[test]
    fn simple_mappings_where_the_full_mapping_has_several_characters() {
        assert_eq!(JavaCase::upper('ß'), 'ß');
        assert_eq!(JavaCase::upper('\u{1F80}'), '\u{1F88}');
        assert_eq!(JavaCase::upper('\u{1FB3}'), '\u{1FBC}');
        assert_eq!(JavaCase::lower('\u{130}'), 'i');
    }

    #[test]
    fn ranges_gain_the_characters_that_map_into_them() {
        let extras = JavaCase::range_extras('a', 'z');
        for c in ['A', 'Z', '\u{130}', '\u{131}', '\u{17F}', '\u{212A}'] {
            assert!(extras.contains(&c), "{c:?}");
        }
        assert!(!JavaCase::range_extras('A', 'Z').contains(&'\u{130}'));
    }
}
