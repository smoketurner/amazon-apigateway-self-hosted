//! IAM's wildcard matching: `*` matches any run of characters and `?` exactly
//! one. Used for the `Action` and `Resource` elements of policy statements.

/// Whether letters match regardless of case. IAM action names are
/// case-insensitive; resource ARNs are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaseSensitivity {
    Sensitive,
    Insensitive,
}

/// A policy element value with `*` and `?` wildcards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Glob {
    pattern: Vec<char>,
    case: CaseSensitivity,
}

impl Glob {
    pub(crate) fn new(pattern: &str, case: CaseSensitivity) -> Self {
        Self {
            pattern: pattern.chars().collect(),
            case,
        }
    }

    /// Policy variables (`${aws:username}`) are substituted by IAM before
    /// matching. This gateway does not substitute them, so a pattern holding one
    /// cannot be evaluated.
    pub(crate) fn has_variable(&self) -> bool {
        self.pattern.windows(2).any(|pair| pair == ['$', '{'])
    }

    fn chars_equal(&self, pattern: char, text: char) -> bool {
        match self.case {
            CaseSensitivity::Sensitive => pattern == text,
            CaseSensitivity::Insensitive => pattern.to_lowercase().eq(text.to_lowercase()),
        }
    }

    /// Whether the whole of `text` matches. Runs in time proportional to the
    /// product of the lengths at worst, with no recursion.
    pub(crate) fn matches(&self, text: &str) -> bool {
        let text: Vec<char> = text.chars().collect();
        let mut pattern_at = 0_usize;
        let mut text_at = 0_usize;
        // Where the most recent `*` was, and how much text it has absorbed.
        let mut backtrack: Option<(usize, usize)> = None;
        while let Some(&current) = text.get(text_at) {
            match self.pattern.get(pattern_at) {
                Some('*') => {
                    backtrack = Some((pattern_at, text_at));
                    pattern_at = pattern_at.saturating_add(1);
                }
                Some(&expected) if expected == '?' || self.chars_equal(expected, current) => {
                    pattern_at = pattern_at.saturating_add(1);
                    text_at = text_at.saturating_add(1);
                }
                Some(_) | None => {
                    let Some((star_at, absorbed_to)) = backtrack else {
                        return false;
                    };
                    let next = absorbed_to.saturating_add(1);
                    backtrack = Some((star_at, next));
                    pattern_at = star_at.saturating_add(1);
                    text_at = next;
                }
            }
        }
        self.pattern
            .get(pattern_at..)
            .is_some_and(|rest| rest.iter().all(|&c| c == '*'))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn exact(pattern: &str, text: &str) -> bool {
        Glob::new(pattern, CaseSensitivity::Sensitive).matches(text)
    }

    #[test]
    fn wildcards_match_as_iam_does() {
        assert!(exact("*", ""));
        assert!(exact("*", "anything"));
        assert!(exact("a*c", "abc"));
        assert!(exact("a*c", "ac"));
        assert!(exact("a?c", "abc"));
        assert!(!exact("a?c", "ac"));
        assert!(!exact("a?c", "abbc"));
        assert!(exact("a*b*c", "aXXbYYc"));
        assert!(!exact("a*b*c", "aXXbYY"));
        assert!(exact("**x", "x"));
        assert!(!exact("", "x"));
        assert!(exact("", ""));
    }

    #[test]
    fn method_arns_match_resource_patterns() {
        let arn = "arn:aws:execute-api:us-east-1:123456789012:abc/prod/GET/pets/7";
        assert!(exact("arn:aws:execute-api:*:*:abc/*/GET/*", arn));
        assert!(exact(arn, arn));
        assert!(!exact("arn:aws:execute-api:*:*:abc/*/POST/*", arn));
        assert!(!exact("arn:aws:execute-api:*:*:abc/prod/GET/pets", arn));
        assert!(!exact("arn:aws:execute-api:*:*:other/*", arn));
    }

    #[test]
    fn case_sensitivity_follows_the_element() {
        let action = Glob::new("execute-api:Invoke", CaseSensitivity::Insensitive);
        assert!(action.matches("EXECUTE-API:invoke"));
        assert!(!exact("GET", "get"));
    }

    #[test]
    fn matching_is_per_character_not_per_byte() {
        assert!(exact("caf?", "caf\u{e9}"));
        assert!(!exact("caf??", "caf\u{e9}"));
    }

    #[test]
    fn policy_variables_are_detected() {
        assert!(Glob::new("arn:*/${aws:username}/*", CaseSensitivity::Sensitive).has_variable());
        assert!(!Glob::new("arn:*/$x/{y}", CaseSensitivity::Sensitive).has_variable());
    }

    #[test]
    fn pathological_patterns_finish() {
        let pattern = "*a".repeat(200);
        let text = "a".repeat(2000);
        assert!(exact(&pattern, &text));
        assert!(!exact(&format!("{pattern}b"), &text));
    }

    /// A direct recursive definition to check the iterative matcher against.
    fn reference(pattern: &[char], text: &[char]) -> bool {
        match pattern.split_first() {
            None => text.is_empty(),
            Some(('*', rest)) => {
                (0..=text.len()).any(|skip| reference(rest, text.split_at(skip).1))
            }
            Some((&p, rest)) => text
                .split_first()
                .is_some_and(|(&t, tail)| (p == '?' || p == t) && reference(rest, tail)),
        }
    }

    proptest! {
        #[test]
        fn agrees_with_the_recursive_definition(
            pattern in "[ab*?]{0,8}",
            text in "[ab]{0,10}",
        ) {
            let expected = reference(
                &pattern.chars().collect::<Vec<_>>(),
                &text.chars().collect::<Vec<_>>(),
            );
            prop_assert_eq!(exact(&pattern, &text), expected);
        }

        #[test]
        fn a_literal_pattern_matches_only_itself(text in "[a-c/:]{0,12}", other in "[a-c/:]{0,12}") {
            prop_assert!(exact(&text, &text));
            prop_assert_eq!(exact(&text, &other), text == other);
        }
    }
}
