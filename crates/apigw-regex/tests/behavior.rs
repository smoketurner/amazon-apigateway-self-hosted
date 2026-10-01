//! Behavior of the public API that the Java fixtures do not cover: limits, error typing, and
//! the examples from the `java.util.regex` documentation.

#![expect(clippy::unwrap_used, reason = "test code")]

use apigw_regex::{
    JavaRegex, RegexError, RegexOptions, Replacement, ReplacementError, Unsupported,
};

fn regex(pattern: &str) -> JavaRegex {
    JavaRegex::new(pattern).unwrap()
}

#[test]
fn backtrack_limit_is_a_typed_error() {
    let options = RegexOptions::default().with_backtrack_limit(5_000);
    let regex = JavaRegex::with_options(r"(a|aa)+\1c", &options).unwrap();
    let input = format!("{}b", "a".repeat(40));
    assert_eq!(
        regex.matches(&input),
        Err(RegexError::BacktrackLimitExceeded)
    );
    assert_eq!(regex.find(&input), Err(RegexError::BacktrackLimitExceeded));
    assert_eq!(
        regex.replace_all(&input, &Replacement::from("x")),
        Err(RegexError::BacktrackLimitExceeded)
    );
    assert_eq!(
        regex.split(&input, 0),
        Err(RegexError::BacktrackLimitExceeded)
    );
}

#[test]
fn linear_patterns_are_not_subject_to_the_backtrack_limit() {
    let options = RegexOptions::default().with_backtrack_limit(1);
    let regex = JavaRegex::with_options(r"(a+)+b", &options).unwrap();
    assert!(!regex.matches(&format!("{}c", "a".repeat(5_000))).unwrap());
}

#[test]
fn oversized_programs_are_rejected_at_compile_time() {
    let options = RegexOptions::default().with_size_limit(10_000);
    let err = JavaRegex::with_options(r"((a{100}){100}){100}", &options).unwrap_err();
    assert!(matches!(err, RegexError::Engine(_)), "{err:?}");
    assert!(err.is_untranslatable());
}

#[test]
fn nesting_beyond_the_limit_is_rejected_without_overflowing_the_stack() {
    let pattern = format!("{}a{}", "(".repeat(5_000), ")".repeat(5_000));
    assert!(matches!(
        JavaRegex::new(&pattern),
        Err(RegexError::TooDeep { .. })
    ));
    let classes = format!("{}a{}", "[".repeat(5_000), "]".repeat(5_000));
    assert!(matches!(
        JavaRegex::new(&classes),
        Err(RegexError::TooDeep { .. })
    ));
}

#[test]
fn syntax_errors_and_untranslatable_constructs_are_distinct() {
    let syntax = JavaRegex::new("(a").unwrap_err();
    assert!(matches!(syntax, RegexError::Syntax { .. }));
    assert!(!syntax.is_untranslatable());

    let unsupported = JavaRegex::new(r"\G").unwrap_err();
    assert!(matches!(
        unsupported,
        RegexError::Unsupported {
            construct: Unsupported::EndOfPreviousMatch,
            index: 0
        }
    ));
    assert!(unsupported.is_untranslatable());
    assert!(unsupported.to_string().contains(r"\G"));
}

#[test]
fn syntax_error_reports_the_character_index() {
    let err = JavaRegex::new("ab*+*").unwrap_err();
    assert!(
        matches!(err, RegexError::Syntax { index: 4, .. }),
        "{err:?}"
    );
}

#[test]
fn javadoc_split_examples() {
    let colon = regex(":");
    assert_eq!(colon.split("boo:and:foo", 2).unwrap(), ["boo", "and:foo"]);
    assert_eq!(
        colon.split("boo:and:foo", 5).unwrap(),
        ["boo", "and", "foo"]
    );
    assert_eq!(
        colon.split("boo:and:foo", -2).unwrap(),
        ["boo", "and", "foo"]
    );
    let o = regex("o");
    assert_eq!(
        o.split("boo:and:foo", 5).unwrap(),
        ["b", "", ":and:f", "", ""]
    );
    assert_eq!(
        o.split("boo:and:foo", -2).unwrap(),
        ["b", "", ":and:f", "", ""]
    );
    assert_eq!(o.split("boo:and:foo", 0).unwrap(), ["b", "", ":and:f"]);
}

#[test]
fn split_of_empty_input_keeps_one_empty_piece() {
    assert_eq!(regex(",").split("", 0).unwrap(), [""]);
}

#[test]
fn find_iter_reports_empty_matches_like_matcher_find() {
    let spans: Vec<_> = regex("a*")
        .find_iter("baaab")
        .map(|m| m.map(|m| (m.start(), m.end())))
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(spans, [(0, 0), (1, 4), (4, 4), (5, 5)]);
}

#[test]
fn find_iter_steps_over_whole_characters() {
    let spans: Vec<_> = regex("")
        .find_iter("é😀")
        .map(|m| m.map(|m| m.start()))
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(spans, [0, 2, 6]);
}

#[test]
fn matches_requires_the_whole_input_even_with_alternation() {
    assert!(regex("a|ab").matches("ab").unwrap());
    assert!(regex("a|ab").find("xab").unwrap().is_some());
    assert!(!regex("abc").matches("abcd").unwrap());
}

#[test]
fn group_lookup_by_name_and_number() {
    let regex = regex(r"(?<year>\d{4})-(\d{2})(?<day>-\d{2})?");
    assert_eq!(regex.group_count(), 3);
    assert_eq!(regex.group_index("year"), Some(1));
    assert_eq!(regex.group_index("day"), Some(3));
    assert_eq!(regex.group_index("month"), None);
    let captures = regex.captures("2024-05").unwrap().unwrap();
    assert_eq!(captures.len(), 4);
    assert_eq!(captures.get(2).map(|m| m.as_str()), Some("05"));
    assert!(captures.get(3).is_none());
    assert!(captures.get(9).is_none());
}

#[test]
fn replacement_errors_surface_only_when_a_match_is_expanded() {
    let regex = regex("a");
    let bad = Replacement::from("$");
    assert_eq!(regex.replace_all("xyz", &bad).unwrap(), "xyz");
    assert_eq!(
        regex.replace_all("xay", &bad),
        Err(RegexError::Replacement(ReplacementError::MissingGroupIndex))
    );
}

#[test]
fn replacement_error_variants() {
    let regex = regex("(?<n>a)");
    let cases = [
        ("\\", ReplacementError::MissingEscapedCharacter),
        ("$", ReplacementError::MissingGroupIndex),
        ("$x", ReplacementError::IllegalGroupReference),
        ("${}", ReplacementError::EmptyGroupName),
        ("${n", ReplacementError::UnclosedGroupName),
        (
            "${1a}",
            ReplacementError::GroupNameStartsWithDigit("1a".into()),
        ),
        ("${zz}", ReplacementError::UnknownGroupName("zz".into())),
        ("$2", ReplacementError::UnknownGroupNumber(2)),
    ];
    for (raw, expected) in cases {
        assert_eq!(
            regex.replace_all("a", &Replacement::from(raw)),
            Err(RegexError::Replacement(expected)),
            "{raw}"
        );
    }
}

#[test]
fn replacement_group_numbers_are_greedy_only_while_the_group_exists() {
    let regex = regex("(a)(b)");
    let out = regex
        .replace_all("ab", &Replacement::from("$10|$21|$100"))
        .unwrap();
    assert_eq!(out, "a0|b1|a00");
}

#[test]
fn quoting_helpers_round_trip() {
    let literal = "a.b*c$1\\E and \\Q";
    let pattern = JavaRegex::quote(literal);
    assert!(regex(&pattern).matches(literal).unwrap());
    let replaced = regex("x")
        .replace_all(
            "x",
            &Replacement::from(Replacement::quote(literal).as_str()),
        )
        .unwrap();
    assert_eq!(replaced, literal);
}

#[test]
fn unicode_character_classes_flag_changes_word_semantics() {
    assert!(!regex(r"\w+").matches("héllo").unwrap());
    assert!(regex(r"(?U)\w+").matches("héllo").unwrap());
}

#[test]
fn ascii_case_insensitivity_does_not_fold_non_ascii() {
    assert!(regex("(?i)k").matches("K").unwrap());
    assert!(!regex("(?i)k").matches("\u{212A}").unwrap());
    assert!(regex("(?iu)k").matches("\u{212A}").unwrap());
}

#[test]
fn dollar_matches_before_a_final_terminator_only() {
    let regex = regex("a$");
    assert!(regex.find("a\n").unwrap().is_some());
    assert!(regex.find("a\r\n").unwrap().is_some());
    assert!(regex.find("a\n\n").unwrap().is_none());
    assert!(regex.find("a\nb").unwrap().is_none());
}
