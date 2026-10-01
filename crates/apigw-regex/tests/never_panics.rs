//! Translation and evaluation must report problems as errors and never panic, whatever the
//! pattern, input, or replacement.

use apigw_regex::{JavaRegex, RegexOptions, Replacement};
use proptest::prelude::*;

const PATTERN_FRAGMENTS: &[&str] = &[
    "a",
    "b",
    "1",
    "é",
    "😀",
    ".",
    "*",
    "+",
    "?",
    "{",
    "}",
    "{2,3}",
    "{0}",
    "{1,}",
    "(",
    ")",
    "(?:",
    "(?i)",
    "(?<n>",
    "(?=",
    "(?!",
    "(?<=",
    "(?<!",
    "(?>",
    "(?x)",
    "(?m)",
    "(?s)",
    "(?U)",
    "(?-i)",
    "|",
    "[",
    "]",
    "[^",
    "&&",
    "-",
    "^",
    "$",
    "\\",
    "\\d",
    "\\D",
    "\\w",
    "\\W",
    "\\s",
    "\\S",
    "\\b",
    "\\B",
    "\\1",
    "\\2",
    "\\k<n>",
    "\\p{L}",
    "\\p{Lower}",
    "\\P{Alpha}",
    "\\Q",
    "\\E",
    "\\x{41}",
    "\\u0041",
    "\\0101",
    "\\cA",
    "\\R",
    "\\h",
    "\\v",
    "\\A",
    "\\z",
    "\\Z",
    "\\G",
    "\\X",
    "#",
    " ",
    "\n",
    "*+",
    "+?",
    "x{99999}",
];

const INPUT_FRAGMENTS: &[&str] = &[
    "a", "b", "1", "é", "😀", "\n", "\r", "\r\n", " ", "_", "-", "\u{2028}",
];

fn from_fragments(fragments: &'static [&'static str], max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(fragments), 0..max).prop_map(|parts| parts.concat())
}

fn exercise(regex: &JavaRegex, input: &str, replacement: &str) {
    let replacement = Replacement::from(replacement);
    drop(regex.matches(input));
    drop(regex.find(input));
    drop(regex.captures(input));
    drop(regex.replace_all(input, &replacement));
    drop(regex.replace_first(input, &replacement));
    drop(regex.split(input, 0));
    drop(regex.split(input, -1));
    drop(regex.split(input, 2));
    for found in regex.find_iter(input) {
        if found.is_err() {
            break;
        }
    }
}

fn options() -> RegexOptions {
    RegexOptions::default()
        .with_backtrack_limit(2_000)
        .with_size_limit(200_000)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_500))]

    #[test]
    fn fragment_patterns_never_panic(
        pattern in from_fragments(PATTERN_FRAGMENTS, 14),
        input in from_fragments(INPUT_FRAGMENTS, 10),
        replacement in from_fragments(&["$", "$0", "$1", "${n}", "\\", "x", "$9"], 5),
    ) {
        if let Ok(regex) = JavaRegex::with_options(&pattern, &options()) {
            exercise(&regex, &input, &replacement);
        }
    }

    #[test]
    fn arbitrary_text_never_panics(
        pattern in any::<String>(),
        input in any::<String>(),
        replacement in any::<String>(),
    ) {
        if let Ok(regex) = JavaRegex::with_options(&pattern, &options()) {
            exercise(&regex, &input, &replacement);
        }
    }

    #[test]
    fn quoted_text_matches_itself(text in any::<String>()) {
        let regex = JavaRegex::with_options(&JavaRegex::quote(&text), &options());
        let regex = regex.map_err(|err| TestCaseError::fail(err.to_string()))?;
        prop_assert!(regex.matches(&text).unwrap_or(false));
    }

    #[test]
    fn quoted_replacement_inserts_text_verbatim(text in any::<String>()) {
        let regex = JavaRegex::new("x")
            .map_err(|err| TestCaseError::fail(err.to_string()))?;
        let replacement = Replacement::from(Replacement::quote(&text).as_str());
        let out = regex.replace_all("x", &replacement)
            .map_err(|err| TestCaseError::fail(err.to_string()))?;
        prop_assert_eq!(out, text);
    }
}
